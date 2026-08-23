{{/* Fail at render time rather than at runtime.

     A missing secret reference should stop `helm install`, not produce a pod
     that crash-loops with an authentication error at 3am. Every required
     reference is checked here. */}}

{{- define "skopos.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "skopos.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "skopos.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "skopos.labels" -}}
app.kubernetes.io/name: {{ include "skopos.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "skopos.requireSecret" -}}
{{- $ctx := index . 0 -}}
{{- $path := index . 1 -}}
{{- $why := index . 2 -}}
{{- if not $ctx.name -}}
{{- fail (printf "%s is required. %s\n\nThis chart ships no default credential: values.yaml is committed, pasted into tickets, and rendered into CI logs, and a working default password is how a development credential reaches production." $path $why) -}}
{{- end -}}
{{- end -}}

{{/* The two identities, checked together so the failure names both. */}}
{{- define "skopos.checkDatabase" -}}
{{- include "skopos.requireSecret" (list .Values.database.migrationSecret "database.migrationSecret.name" "It holds the superuser DSN used by the migration Job.") -}}
{{- include "skopos.requireSecret" (list .Values.database.runtimeSecret "database.runtimeSecret.name" "It holds the UNPRIVILEGED DSN the pods serve with. Without it the application would fall back to the superuser, and PostgreSQL row-level security does not apply to a superuser at all - tenancy would be enforced by nothing while the schema still reviewed as multi-tenant.") -}}
{{- include "skopos.requireSecret" (list .Values.database.appPasswordSecret "database.appPasswordSecret.name" "It sets the unprivileged role's password during migration.") -}}
{{- end -}}

{{/* Environment shared by the API pods and the scheduler. */}}
{{- define "skopos.runtimeEnv" -}}
- name: SKOPOS_APP_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.database.runtimeSecret.name }}
      key: {{ .Values.database.runtimeSecret.key }}
- name: SKOPOS_ORG_ID
  value: {{ .Values.tenancy.orgId | quote }}
{{- if .Values.auth.pendingSecret.name }}
- name: SKOPOS_PENDING_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ .Values.auth.pendingSecret.name }}
      key: {{ .Values.auth.pendingSecret.key }}
{{- end }}
{{- if .Values.auth.bootstrapSecret.name }}
- name: SKOPOS_BOOTSTRAP_USER
  valueFrom:
    secretKeyRef:
      name: {{ .Values.auth.bootstrapSecret.name }}
      key: username
- name: SKOPOS_BOOTSTRAP_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.auth.bootstrapSecret.name }}
      key: password
{{- end }}
{{- if .Values.api.tokenSecret.name }}
- name: SKOPOS_API_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.api.tokenSecret.name }}
      key: {{ .Values.api.tokenSecret.key }}
{{- end }}
{{- if .Values.alerting.onScan }}
- name: SKOPOS_ALERT_ON_SCAN
  value: "1"
{{- end }}
{{- if .Values.alerting.webhookSecret.name }}
- name: SKOPOS_ALERT_WEBHOOK
  valueFrom:
    secretKeyRef:
      name: {{ .Values.alerting.webhookSecret.name }}
      key: {{ .Values.alerting.webhookSecret.key }}
{{- end }}
{{- if .Values.itsm.onScan }}
- name: SKOPOS_ITSM_ON_SCAN
  value: "1"
{{- end }}
{{- if .Values.itsm.webhookSecret.name }}
- name: SKOPOS_ITSM_WEBHOOK
  valueFrom:
    secretKeyRef:
      name: {{ .Values.itsm.webhookSecret.name }}
      key: {{ .Values.itsm.webhookSecret.key }}
{{- end }}
{{- if .Values.itsm.tokenSecret.name }}
- name: SKOPOS_ITSM_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.itsm.tokenSecret.name }}
      key: {{ .Values.itsm.tokenSecret.key }}
{{- end }}
{{- end -}}
