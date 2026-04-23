-- Add log_path column to store path to captured container stdout/stderr
ALTER TABLE runs ADD COLUMN log_path TEXT;
