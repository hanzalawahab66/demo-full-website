-- Create database (run once)
CREATE DATABASE IF NOT EXISTS `nsm_autos` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE `nsm_autos`;

-- Users table
CREATE TABLE IF NOT EXISTS `users` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(100) NOT NULL,
  `email` VARCHAR(255) NOT NULL,
  `password` VARCHAR(255) NOT NULL, -- bcrypt hash stored here
  `role` ENUM('buyer','seller','admin','superadmin','listing_editor','user_manager') NOT NULL,
  `status` ENUM('pending','approved','rejected','suspended') NOT NULL DEFAULT 'pending',
  `phone_number` VARCHAR(30) NULL,
  `country` VARCHAR(100) NULL,
  `company_name_korean` VARCHAR(255) NULL,
  `company_name_english` VARCHAR(255) NULL,
  `export_items` VARCHAR(100) NULL,
  `available_languages` TEXT NULL,
  `representative_name` VARCHAR(255) NULL,
  `company_tel` VARCHAR(50) NULL,
  `company_logo_url` VARCHAR(255) NULL,
  `company_address` VARCHAR(255) NULL,
  `detailed_address` VARCHAR(255) NULL,
  `establishment_date` DATE NULL,
  `business_registration_url` VARCHAR(255) NULL,
  `business_registration_document` VARCHAR(255) NULL,
  `company_introduction` TEXT NULL,
  `bank_name` VARCHAR(255) NULL,
  `account_number` VARCHAR(255) NULL,
  `account_holder_name` VARCHAR(255) NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Upgrade existing users table: add status and new columns
-- Run these ALTERs if your table already exists without the new fields
ALTER TABLE `users`
  ADD COLUMN `status` ENUM('pending','approved','rejected','suspended') NOT NULL DEFAULT 'pending' AFTER `role`;

ALTER TABLE `users` ADD COLUMN `phone_number` VARCHAR(30) NULL;
ALTER TABLE `users` ADD COLUMN `country` VARCHAR(100) NULL;
ALTER TABLE `users` ADD COLUMN `company_name_korean` VARCHAR(255) NULL;
ALTER TABLE `users` ADD COLUMN `company_name_english` VARCHAR(255) NULL;
ALTER TABLE `users` ADD COLUMN `export_items` VARCHAR(100) NULL;
ALTER TABLE `users` ADD COLUMN `available_languages` TEXT NULL;
ALTER TABLE `users` ADD COLUMN `representative_name` VARCHAR(255) NULL;
ALTER TABLE `users` ADD COLUMN `company_tel` VARCHAR(50) NULL;
ALTER TABLE `users` ADD COLUMN `company_logo_url` VARCHAR(255) NULL;
ALTER TABLE `users` ADD COLUMN `company_address` VARCHAR(255) NULL;
ALTER TABLE `users` ADD COLUMN `detailed_address` VARCHAR(255) NULL;
ALTER TABLE `users` ADD COLUMN `establishment_date` DATE NULL;
ALTER TABLE `users` ADD COLUMN `business_registration_url` VARCHAR(255) NULL;
ALTER TABLE `users` ADD COLUMN `business_registration_document` VARCHAR(255) NULL;
ALTER TABLE `users` ADD COLUMN `company_introduction` TEXT NULL;
ALTER TABLE `users` ADD COLUMN `bank_name` VARCHAR(255) NULL;
ALTER TABLE `users` ADD COLUMN `account_number` VARCHAR(255) NULL;
ALTER TABLE `users` ADD COLUMN `account_holder_name` VARCHAR(255) NULL;

-- If status column exists but lacks new ENUM values, modify it:
ALTER TABLE `users` MODIFY COLUMN `status` ENUM('pending','approved','rejected','suspended') NOT NULL DEFAULT 'pending';

-- Expand role enum to include staff roles
ALTER TABLE `users` MODIFY COLUMN `role` ENUM('buyer','seller','admin','superadmin','listing_editor','user_manager') NOT NULL;

-- Categories table (nested, self-referencing via parent_id)
CREATE TABLE IF NOT EXISTS `categories` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(255) NOT NULL,
  `parent_id` INT UNSIGNED NULL,
  `image_url` VARCHAR(255) NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_parent_id` (`parent_id`),
  CONSTRAINT `fk_categories_parent`
    FOREIGN KEY (`parent_id`) REFERENCES `categories`(`id`)
    ON DELETE SET NULL
    ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Upgrade existing categories table: add image_url and created_at if missing
ALTER TABLE `categories` ADD COLUMN `image_url` VARCHAR(255) NULL;
ALTER TABLE `categories` ADD COLUMN `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP;