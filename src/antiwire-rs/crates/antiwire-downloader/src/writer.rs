use std::io::Write;
use std::path::PathBuf;

use tokio::sync::mpsc::{self, Sender};
use tokio::task::JoinHandle;

use crate::error::DownloadError;

pub(crate) struct AtomicWriter {
    sender: Sender<WriterCommand>,
    task: JoinHandle<std::io::Result<()>>,
}

impl AtomicWriter {
    pub(crate) fn new(destination: PathBuf) -> Self {
        let (sender, mut receiver) = mpsc::channel(32);
        let task = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let file = atomic_write_file::AtomicWriteFile::open(destination)?;
            let mut writer = std::io::BufWriter::with_capacity(64 * 1024, file);
            while let Some(command) = receiver.blocking_recv() {
                match command {
                    WriterCommand::Chunk(bytes) => writer.write_all(&bytes)?,
                    WriterCommand::Commit => {
                        writer.flush()?;
                        let inner = writer
                            .into_inner()
                            .map_err(std::io::IntoInnerError::into_error)?;
                        return inner.commit();
                    }
                }
            }
            Err(writer_closed())
        });

        Self { sender, task }
    }

    pub(crate) async fn write(&self, bytes: Vec<u8>) -> std::io::Result<()> {
        self.sender
            .send(WriterCommand::Chunk(bytes))
            .await
            .map_err(|_| writer_closed())
    }

    pub(crate) async fn commit(&self) -> std::io::Result<()> {
        self.sender
            .send(WriterCommand::Commit)
            .await
            .map_err(|_| writer_closed())
    }

    pub(crate) async fn finish(self) -> std::io::Result<()> {
        drop(self.sender);
        self.task
            .await
            .map_err(|error| std::io::Error::other(format!("atomic writer failed: {error}")))?
    }

    pub(crate) async fn complete(
        self,
        result: Result<(), DownloadError>,
    ) -> Result<(), DownloadError> {
        let writer_result = self.finish().await;
        match result {
            Ok(()) => writer_result.map_err(DownloadError::Io),
            Err(error) => match writer_result {
                // A genuine writer failure (e.g. the destination could not be
                // opened) is more informative than the aborted download error.
                Err(writer_err) if !is_writer_closed(&writer_err) => {
                    Err(DownloadError::Io(writer_err))
                }
                _ => Err(error),
            },
        }
    }
}

enum WriterCommand {
    Chunk(Vec<u8>),
    Commit,
}

#[derive(Debug)]
struct WriterClosed;

impl std::fmt::Display for WriterClosed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("atomic writer stopped before commit")
    }
}

impl std::error::Error for WriterClosed {}

fn writer_closed() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, WriterClosed)
}

fn is_writer_closed(error: &std::io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.downcast_ref::<WriterClosed>().is_some())
}

#[cfg(test)]
mod tests {
    use super::AtomicWriter;
    use crate::DownloadError;

    #[tokio::test]
    async fn missing_commit_is_reported_as_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out.txt");
        let writer = AtomicWriter::new(dest.clone());
        writer.write(b"data".to_vec()).await.expect("write");

        let error = writer
            .complete(Ok(()))
            .await
            .expect_err("missing commit must not report success");
        assert!(matches!(error, DownloadError::Io(_)));
        assert!(!dest.exists(), "uncommitted destination must not exist");
    }

    #[tokio::test]
    async fn aborted_write_returns_download_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out.txt");
        let writer = AtomicWriter::new(dest.clone());
        writer.write(b"data".to_vec()).await.expect("write");

        let error = writer
            .complete(Err(DownloadError::IdleTimeout))
            .await
            .expect_err("aborted download");
        assert!(matches!(error, DownloadError::IdleTimeout));
        assert!(!dest.exists());
    }
}
