DROP DATABASE IF EXISTS irc_chat;
CREATE DATABASE irc_chat CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE irc_chat;

CREATE TABLE users (
  id                INT AUTO_INCREMENT PRIMARY KEY,
  username          VARCHAR(32)  NOT NULL UNIQUE,
  password          VARCHAR(255) NOT NULL,
  color             VARCHAR(16)  NOT NULL DEFAULT 'u-green',
  bio               VARCHAR(255) DEFAULT NULL,
  status            VARCHAR(64)  DEFAULT NULL,
  avatar            VARCHAR(255) DEFAULT NULL,
  pubkey            TEXT         DEFAULT NULL,
  ws_token          VARCHAR(64)  DEFAULT NULL,       -- tidak dipakai lagi, dibiarkan untuk kompatibilitas
  ws_token_expires  DATETIME     DEFAULT NULL,
  last_seen         DATETIME     DEFAULT NULL,
  created_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_ws_token (ws_token),
  INDEX idx_last_seen (last_seen)                    -- BARU: untuk query online users
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE messages (
  id          BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id     INT          NULL,
  username    VARCHAR(32)  NOT NULL,
  target      VARCHAR(32)  DEFAULT NULL,
  color       VARCHAR(16)  NOT NULL DEFAULT 'u-green',
  type        ENUM('msg','join','part','system','pm') NOT NULL DEFAULT 'msg',
  body        TEXT         NOT NULL,
  created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_created (created_at),
  INDEX idx_target (target),
  INDEX idx_type_id (type, id),                       -- BARU: untuk poll messages
  INDEX idx_pm_lookup (type, id, username, target),   -- BARU: untuk poll PM
  CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- BARU: tabel typing indicator (auto-expire via query time filter)
CREATE TABLE typing_state (
  username    VARCHAR(32) PRIMARY KEY,
  updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_updated (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- BARU: event join/part untuk replay ke client baru
CREATE TABLE user_events (
  id          BIGINT AUTO_INCREMENT PRIMARY KEY,
  username    VARCHAR(32) NOT NULL,
  type        ENUM('join','part') NOT NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- User aplikasi
CREATE USER IF NOT EXISTS 'irc_app'@'localhost' IDENTIFIED BY 'GantiPasswordKuat123!';
GRANT SELECT, INSERT, UPDATE, DELETE ON irc_chat.* TO 'irc_app'@'localhost';
FLUSH PRIVILEGES;
