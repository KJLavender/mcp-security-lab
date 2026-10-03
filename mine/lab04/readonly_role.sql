-- Lab 04 - 我的修補的「主控制點」：資料庫層的唯讀角色。
-- MCP server 用 mcp_ro 連線，而不是 POSTGRES_USER（superuser）。
-- 就算 SQL 字串檢查全被繞過，這個角色本身也寫不了、讀不了伺服器檔案。
CREATE ROLE mcp_ro LOGIN PASSWORD 'ro_password'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;

ALTER ROLE mcp_ro SET default_transaction_read_only = on;
ALTER ROLE mcp_ro SET statement_timeout = '5s';

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO mcp_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO mcp_ro;
