use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};

/// Async read adapter that aborts once a cumulative byte ceiling is crossed.
pub(crate) struct ByteLimitedReader<R> {
    inner: R,
    max_bytes: u64,
    read: u64,
    limit_exceeded: bool,
}

impl<R> ByteLimitedReader<R> {
    #[must_use]
    pub(crate) fn new(inner: R, max_bytes: u64) -> Self {
        Self {
            inner,
            max_bytes,
            read: 0,
            limit_exceeded: false,
        }
    }

    #[must_use]
    pub(crate) fn limit_exceeded(&self) -> bool {
        self.limit_exceeded
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ByteLimitedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let read = (buf.filled().len() - before) as u64;
            if read > 0 {
                self.read = self.read.saturating_add(read);
                if self.read > self.max_bytes {
                    self.limit_exceeded = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("download exceeded the {} byte limit", self.max_bytes),
                    )));
                }
            }
        }
        poll
    }
}

#[cfg(test)]
mod tests {
    use super::ByteLimitedReader;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn limited_reader_aborts_over_cap() {
        let data = b"0123456789";
        let mut limited = ByteLimitedReader::new(&data[..], 5);
        let mut buf = [0_u8; 3];
        let first = limited.read(&mut buf).await.expect("first read");
        assert_eq!(first, 3);
        let err = limited.read(&mut buf).await.expect_err("over cap");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
