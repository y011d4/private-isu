USE `isuconp`;

-- DROP TABLE IF EXISTS `comments`;
DROP INDEX `post_id_created_at_idx` ON `comments`;
CREATE INDEX `post_id_created_at_idx` ON `comments`(`post_id`, `created_at` DESC);
DROP INDEX `created_at_idx` ON `posts`;
CREATE INDEX `created_at_idx` ON `posts`(`created_at` DESC);
DROP INDEX `user_id_created_at_idx` ON `posts`;
CREATE INDEX `user_id_created_at_idx` ON `posts`(`user_id`, `created_at` DESC);
DROP INDEX `user_id_idx` ON `comments`;
CREATE INDEX `user_id_idx` ON `comments`(`user_id`);

-- DROP TABLE IF EXISTS `posts`;
-- CREATE TABLE `posts` (
--   `id` int NOT NULL AUTO_INCREMENT,
--   `user_id` int NOT NULL,
--   `mime` varchar(64) NOT NULL,
--   `imgdata` mediumblob NOT NULL,
--   `body` text NOT NULL,
--   `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
--   PRIMARY KEY (`id`)
-- ) ENGINE=InnoDB AUTO_INCREMENT=10004 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- DROP TABLE IF EXISTS `users`;
-- CREATE TABLE `users` (
--   `id` int NOT NULL AUTO_INCREMENT,
--   `account_name` varchar(64) NOT NULL,
--   `passhash` varchar(128) NOT NULL,
--   `authority` tinyint(1) NOT NULL DEFAULT '0',
--   `del_flg` tinyint(1) NOT NULL DEFAULT '0',
--   `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
--   PRIMARY KEY (`id`),
--   UNIQUE KEY `account_name` (`account_name`)
-- ) ENGINE=InnoDB AUTO_INCREMENT=1009 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
