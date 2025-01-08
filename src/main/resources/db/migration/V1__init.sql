CREATE TABLE IF NOT EXISTS roles
(
    id   serial PRIMARY KEY,
    name varchar(50) NOT NULL
);

INSERT INTO roles (name)
VALUES ('ROLE_USER'),
       ('ROLE_SELLER'),
       ('ROLE_MODER'),
       ('ROLE_ADMIN');

CREATE TABLE IF NOT EXISTS users
(
    id       bigserial PRIMARY KEY,
    username varchar(30) NOT NULL UNIQUE,
    password varchar(80) NOT NULL
);

CREATE TABLE IF NOT EXISTS users_roles
(
    user_id bigint NOT NULL,
    role_id int    NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tokens
(
    id         bigserial PRIMARY KEY,
    token      varchar(255) NOT NULL,
    expired    timestamp    NOT NULL,
    username   varchar(255) NOT NULL
);

INSERT INTO users (username, password) --пароль '111111'
VALUES ('user2025', '$2a$10$OcuToltJZk5qEnomJ8n.Nu2lmAIYxlOumt52OZ0Q2.WIVOkLduz0C'),
       ('Administrator', '$2a$10$kcFepNBcTE6m/zqiAyf7PO6X8iXE2f3KlmbKGzz7x.bnhs14CsrlK');

INSERT INTO users_roles (user_id, role_id)
VALUES (1, 1), -- user2025 - ROLE_USER
       (1, 2), -- user2025 - ROLE_SELLER
       (2, 4); -- Administrator - ROLE_ADMIN
