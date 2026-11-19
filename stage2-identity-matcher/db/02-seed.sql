-- =============================================================================
-- CampusShield - Stage 2: starting data
-- Runs once, after 01-schema.sql. Change these rows to match the real
-- timetable and the university's policy.
-- =============================================================================

-- Domain categories (Table 5.6 of the thesis). A subdomain matches its parent domain.
-- WhatsApp, Telegram, LinkedIn and Quora are deliberately NOT listed (used for study).
INSERT INTO domain_categories (domain, category) VALUES
    -- Facebook / Messenger
    ('facebook.com',      'social-media'),
    ('facebook.net',      'social-media'),
    ('fbcdn.net',         'social-media'),
    ('fb.com',            'social-media'),
    ('messenger.com',     'social-media'),
    ('fbsbx.com',         'social-media'),
    -- Instagram
    ('instagram.com',     'social-media'),
    ('cdninstagram.com',  'social-media'),
    -- TikTok
    ('tiktok.com',        'social-media'),
    ('tiktokcdn.com',     'social-media'),
    ('tiktokv.com',       'social-media'),
    -- Snapchat
    ('snapchat.com',      'social-media'),
    ('sc-cdn.net',        'social-media'),
    -- X (Twitter)
    ('x.com',             'social-media'),
    ('twitter.com',       'social-media'),
    -- Threads
    ('threads.net',       'social-media'),
    ('threads.com',       'social-media'),
    -- Pinterest
    ('pinterest.com',     'social-media'),
    ('pinimg.com',        'social-media'),
    -- Reddit
    ('reddit.com',        'social-media'),
    ('redditmedia.com',   'social-media'),
    ('redditstatic.com',  'social-media'),
    ('redd.it',           'social-media'),
    -- Discord
    ('discord.com',       'social-media'),
    ('discord.gg',        'social-media'),
    ('discordapp.com',    'social-media'),
    ('discordapp.net',    'social-media'),
    -- Snack Video, Likee, Bigo Live, Tumblr
    ('snackvideo.com',    'social-media'),
    ('likee.video',       'social-media'),
    ('bigo.tv',           'social-media'),
    ('tumblr.com',        'social-media'),
    -- YouTube
    ('youtube.com',       'video-streaming'),
    ('googlevideo.com',   'video-streaming'),
    ('ytimg.com',         'video-streaming'),
    ('youtu.be',          'video-streaming'),
    -- Netflix
    ('netflix.com',       'video-streaming'),
    -- Twitch
    ('twitch.tv',         'video-streaming'),
    ('ttvnw.net',         'video-streaming'),
    ('jtvnw.net',         'video-streaming');


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
