-- Schema SQL para referência (DDL das entidades)
-- Este arquivo é opcional mas serve como documentação das tabelas geradas pelo Hibernate

CREATE TABLE users (
    id UUID PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at timestamptz DEFAULT now()
);

CREATE TABLE roles (
    id UUID PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE permissions (
    id UUID PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE user_roles (
    user_id UUID REFERENCES users(id),
    role_id UUID REFERENCES roles(id),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE role_permissions (
    role_id UUID REFERENCES roles(id),
    permission_id UUID REFERENCES permissions(id),
    PRIMARY KEY (role_id, permission_id)
);

-- Indexes para otimização
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_roles_name ON roles(name);
CREATE INDEX idx_permissions_name ON permissions(name);
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission_id ON role_permissions(permission_id);