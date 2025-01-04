create table users
(
    id       bigserial,
    username varchar(30) not null unique,
    password varchar(80) not null,
    primary key (id)
);

create table roles
(
    id   serial,
    name varchar(50) not null,
    primary key (id)
);

CREATE TABLE users_roles
(
    user_id bigint not null,
    role_id int    not null,
    primary key (user_id, role_id),
    foreign key (user_id) references users (id),
    foreign key (role_id) references roles (id)
);

insert into roles (name)
values ('ROLE_USER'), ('ROLE_SELLER'), ('ROLE_MODER'), ('ROLE_ADMIN');

insert into users (username, password)
values ('user2025', '$2a$10$OcuToltJZk5qEnomJ8n.Nu2lmAIYxlOumt52OZ0Q2.WIVOkLduz0C'),
       ('Administrator', '$2a$10$kcFepNBcTE6m/zqiAyf7PO6X8iXE2f3KlmbKGzz7x.bnhs14CsrlK');

insert into users_roles (user_id, role_id)
values (1, 1),
       (1, 2),
       (2, 4);