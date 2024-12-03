-- Add migration script here
CREATE TABLE questions (
    id INTEGER PRIMARY KEY,
    question TEXT NOT NULL,
    submitted_time INTEGER NOT NULL,
    content_warning TEXT
) STRICT;

CREATE TABLE answers (
    id INTEGER PRIMARY KEY REFERENCES questions(id) ON DELETE CASCADE,
    answer_time INTEGER NOT NULL,
    answer TEXT NOT NULL
) STRICT;