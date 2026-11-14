import {
  Activity,
  BellRing,
  Database,
  Globe2,
  HardDrive,
  LockKeyhole,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
} from 'lucide-react';
import { m } from '#lib/i18n/messages.ts';
import type { DnsProtocol } from '#lib/models/dns-providers.ts';
import type { OnboardingChoices } from '#lib/models/onboarding-settings.ts';

/** Props shared by every step that edits the onboarding choices. */
export interface StepProps {
  choices: OnboardingChoices;
  patch: <K extends keyof OnboardingChoices>(key: K, value: OnboardingChoices[K]) => void;
}

export const steps = [
  {
    name: m.onboarding_step_welcome_kicker,
    title: m.onboarding_step_welcome_title,
    lead: m.onboarding_welcome_body,
    icon: ShieldCheck,
  },
  {
    name: m.onboarding_step_dns_kicker,
    title: m.onboarding_step_dns_title,
    lead: m.onboarding_resolver_body,
    icon: LockKeyhole,
  },
  {
    name: m.onboarding_step_blocklists_kicker,
    title: m.onboarding_step_blocklists_title,
    lead: m.onboarding_blocklists_lead,
    icon: Shield,
  },
  {
    name: m.onboarding_step_geoip_kicker,
    title: m.onboarding_step_geoip_title,
    lead: m.onboarding_geoip_body,
    icon: Globe2,
  },
  {
    name: m.onboarding_step_alerts_kicker,
    title: m.onboarding_step_alerts_title,
    lead: m.onboarding_desktop_notifications_body,
    icon: BellRing,
  },
  {
    name: m.onboarding_step_retention_kicker,
    title: m.onboarding_step_retention_title,
    lead: m.onboarding_retention_lead,
    icon: Database,
  },
] as const;

export const protocols: Array<{
  id: DnsProtocol;
  name: () => string;
  summary: () => string;
  detail: () => string;
  recommended?: boolean;
}> = [
  {
    id: 'doh',
    name: m.onboarding_protocol_doh_name,
    summary: m.onboarding_protocol_doh_summary,
    detail: m.onboarding_protocol_doh_detail,
    recommended: true,
  },
  {
    id: 'doh3',
    name: m.onboarding_protocol_doh3_name,
    summary: m.onboarding_protocol_doh3_summary,
    detail: m.onboarding_protocol_doh3_detail,
  },
  {
    id: 'dot',
    name: m.onboarding_protocol_dot_name,
    summary: m.onboarding_protocol_dot_summary,
    detail: m.onboarding_protocol_dot_detail,
  },
  {
    id: 'doq',
    name: m.onboarding_protocol_doq_name,
    summary: m.onboarding_protocol_doq_summary,
    detail: m.onboarding_protocol_doq_detail,
  },
];

export const highlights = [
  { icon: Activity, title: m.onboarding_welcome_see_title, body: m.onboarding_welcome_see_body },
  {
    icon: SlidersHorizontal,
    title: m.onboarding_welcome_control_title,
    body: m.onboarding_welcome_control_body,
  },
  {
    icon: HardDrive,
    title: m.onboarding_welcome_local_title,
    body: m.onboarding_welcome_local_body,
  },
] as const;
