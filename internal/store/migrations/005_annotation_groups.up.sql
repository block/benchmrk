CREATE TABLE annotation_groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL REFERENCES corpus_projects(id) ON DELETE CASCADE,
    name        TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE annotation_group_members (
    group_id      INTEGER NOT NULL REFERENCES annotation_groups(id) ON DELETE CASCADE,
    annotation_id INTEGER NOT NULL REFERENCES annotations(id) ON DELETE CASCADE,
    role          TEXT NOT NULL DEFAULT 'related' CHECK(role IN ('source', 'sink', 'related')),
    PRIMARY KEY (group_id, annotation_id)
);

CREATE INDEX idx_annotation_groups_project ON annotation_groups(project_id);
CREATE INDEX idx_annotation_group_members_annotation ON annotation_group_members(annotation_id);
