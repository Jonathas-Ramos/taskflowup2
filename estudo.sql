

create database task_flowup;

USE `task_flowup`;
 
-- Exclui as tabelas antigas se existirem, evitando conflitos
-- Remove tabelas antigas para evitar conflitos

CREATE TABLE activity_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action_text VARCHAR(255) NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);


-- ==========================
-- TABELA: USERS
-- ==========================
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) NOT NULL UNIQUE,
    email VARCHAR(120) UNIQUE,
    password_hash VARCHAR(128) NOT NULL,
    salt VARCHAR(32) NOT NULL,
    role ENUM('admin', 'funcionario') NOT NULL DEFAULT 'funcionario',
    needs_password_reset BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ==========================
-- TABELA: TASKS
-- ==========================
CREATE TABLE tasks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    priority INT NOT NULL DEFAULT 2,
    due_date DATE,
    completed BOOLEAN NOT NULL DEFAULT FALSE,
    creator_id INT NOT NULL,
    assigned_to_id INT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (creator_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_to_id) REFERENCES users(id) ON DELETE SET NULL
);

-- ==========================
-- TABELA: TASK_COMMENTS
-- ==========================
CREATE TABLE task_comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    task_id INT NOT NULL,
    user_id INT NOT NULL,
    text TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ==========================
-- TABELA: CHAT_MESSAGES
-- ==========================
CREATE TABLE chat_messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    text TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ==========================
-- INSERÇÃO DE USUÁRIO ADMIN INICIAL
-- ==========================
-- (opcional, para login inicial com a chave 'admin-secret-key')
select * from users;
-- Crie manualmente depois se desejar um admin inicial, ex:
-- INSERT INTO users (username, email, password_hash, salt, role)
-- VALUES ('admin', 'admin@email.com', '<hash>', '<salt>', 'admin');
ALTER TABLE users
ADD COLUMN job_title VARCHAR(100) DEFAULT 'Funcionário';
