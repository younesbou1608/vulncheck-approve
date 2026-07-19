-- Migration Sprint 5 : version sûre recommandée par validation.
-- Idempotente : sans effet si la colonne existe déjà (base neuve via 02).
ALTER TABLE validations ADD COLUMN IF NOT EXISTS recommended_version TEXT;
