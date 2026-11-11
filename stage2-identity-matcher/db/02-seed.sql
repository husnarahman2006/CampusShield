-- =============================================================================
-- CampusShield - Stage 2: starting data
-- Runs once, after 01-schema.sql. Change these rows to match the real
-- timetable and the university's policy.
-- =============================================================================

-- Domain categories: the same list the SNI extractor used (Table 5.6 of the thesis).
INSERT INTO domain_categories (domain, category) VALUES
    ('facebook.com',     'social-media'),
    ('fbcdn.net',        'social-media'),
    ('instagram.com',    'social-media'),
    ('cdninstagram.com', 'social-media'),
    ('tiktok.com',       'social-media'),
    ('tiktokcdn.com',    'social-media'),
    ('x.com',            'social-media'),
    ('twitter.com',      'social-media'),
    ('snapchat.com',     'social-media'),
    ('youtube.com',      'video-streaming'),
    ('googlevideo.com',  'video-streaming'),
    ('ytimg.com',        'video-streaming'),
    ('netflix.com',      'video-streaming');


-- Policies.
-- guest   (not verified): most restrictive, blocked at all times (fail-closed).
-- student: blocked during class, allowed outside class.
-- faculty: allowed (e.g. YouTube is used for teaching).
-- admin:   allowed.
INSERT INTO policies (role, category, during_class, outside_class) VALUES
    ('guest',   'social-media',    'BLOCK', 'BLOCK'),
    ('guest',   'video-streaming', 'BLOCK', 'BLOCK'),
    ('student', 'social-media',    'BLOCK', 'ALLOW'),
    ('student', 'video-streaming', 'BLOCK', 'ALLOW'),
    ('faculty', 'social-media',    'ALLOW', 'ALLOW'),
    ('faculty', 'video-streaming', 'ALLOW', 'ALLOW'),
    ('admin',   'social-media',    'ALLOW', 'ALLOW'),
    ('admin',   'video-streaming', 'ALLOW', 'ALLOW');

-- Sample timetable (Monday to Friday). Replace with the real class schedule.
INSERT INTO timetable (day_of_week, start_time, end_time, label) VALUES
    (1, '08:30', '10:00', 'Sample class A'),
    (1, '10:15', '11:45', 'Sample class B'),
    (2, '08:30', '10:00', 'Sample class A'),
    (3, '11:00', '12:30', 'Sample class C'),
    (4, '14:00', '15:30', 'Sample class D'),
    (5, '09:00', '10:30', 'Sample class E');
