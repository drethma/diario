# -*- coding: utf-8 -*-
import streamlit as st
import sqlite3
from datetime import datetime, time
import re
import os
# import shutil # Removido na v12, mas pode adicionar de volta para backup local
import pandas as pd
import math
import hashlib

# --- Configurações Globais ---
DB_FILE = "meu_diario_v13_full_admin.db" # Arquivo SQLite local
DATE_FORMAT = "%d/%m/%Y %H:%M:%S"
DATE_ONLY_FORMAT = "%d/%m/%Y"
ITEMS_PER_PAGE = 5
MOOD_OPTIONS = ("❔", "😊", "😃", "🙂", "😐", "🙁", "😢", "😠", "🎉", "🤔")

# --- Funções Utilitárias ---
def hash_password(password):
  return hashlib.sha256(password.encode()).hexdigest()

# --- Funções de Banco de Dados ---

def get_db_connection():
    try: conn = sqlite3.connect(DB_FILE); conn.row_factory = sqlite3.Row; return conn
    except sqlite3.Error as e: st.error(f"Erro DB Conn: {e}"); return None

def init_db():
    conn = get_db_connection();
    if not conn: st.stop()
    try:
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL COLLATE NOCASE, password_hash TEXT NOT NULL, is_admin INTEGER DEFAULT 0)')
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users (username COLLATE NOCASE);")
        cursor.execute('CREATE TABLE IF NOT EXISTS entries (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, content TEXT NOT NULL, tags TEXT, mood TEXT, FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE)')
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_entries_created_at ON entries (created_at DESC);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_entries_tags ON entries (tags);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_entries_user_id ON entries (user_id);")
        cursor.execute("PRAGMA table_info(users)"); user_columns = [col['name'] for col in cursor.fetchall()]
        if 'is_admin' not in user_columns: st.warning("Adicionando 'is_admin' a users."); cursor.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
        cursor.execute("PRAGMA table_info(entries)"); entry_columns = [col['name'] for col in cursor.fetchall()]
        if 'mood' not in entry_columns: st.warning("Adicionando 'mood' a entries."); cursor.execute("ALTER TABLE entries ADD COLUMN mood TEXT")
        if 'user_id' not in entry_columns: st.warning("Adicionando 'user_id' a entries."); cursor.execute("ALTER TABLE entries ADD COLUMN user_id INTEGER")
        conn.commit()
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1"); admin_count = cursor.fetchone()[0]
        if admin_count == 0:
            cursor.execute("SELECT id FROM users ORDER BY id LIMIT 1"); first_user = cursor.fetchone()
            if first_user: st.info(f"Definindo user ID {first_user['id']} como admin."); cursor.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (first_user['id'],)); conn.commit()
    except sqlite3.Error as e: st.error(f"Erro init DB: {e}"); st.stop()
    finally:
        if conn: conn.close()

def add_user(username, password):
    conn = get_db_connection();
    if not conn: return False, "Erro DB."
    if not username or not username.strip(): return False, "Usuário vazio."
    sql = "INSERT INTO users (username, password_hash) VALUES (?, ?)"
    try:
        cursor = conn.cursor(); hashed_pw = hash_password(password)
        cursor.execute(sql, (username.strip(), hashed_pw)); conn.commit()
        if cursor.lastrowid == 1: # Tornar o primeiro usuário admin
             cursor.execute("UPDATE users SET is_admin = 1 WHERE id = 1"); conn.commit()
             st.info("Primeiro usuário registrado definido como Admin.")
        return True, "Usuário registrado!"
    except sqlite3.IntegrityError: return False, "Usuário já existe."
    except sqlite3.Error as e: return False, f"Erro registro: {e}"
    finally:
        if conn: conn.close()

def verify_user(username, password):
    conn = get_db_connection();
    if not conn: return False, None, None
    sql = "SELECT id, password_hash, is_admin FROM users WHERE username = ? COLLATE NOCASE"
    try: cursor = conn.cursor(); cursor.execute(sql, (username,)); result = cursor.fetchone();
    except sqlite3.Error as e: st.error(f"Erro verificação: {e}"); return False, None, None
    finally:
        if conn: conn.close()
    if result:
        if result['password_hash'] == hash_password(password):
            return True, result['id'], bool(result['is_admin'])
    return False, None, None

def update_user_password(user_id, new_password):
    conn = get_db_connection();
    if not conn: return False, "Erro DB."
    if not new_password or len(new_password) < 4 : return False, "Nova senha inválida (min 4 chars)."
    sql = "UPDATE users SET password_hash = ? WHERE id = ?"
    try:
        cursor = conn.cursor(); new_hashed_pw = hash_password(new_password)
        cursor.execute(sql, (new_hashed_pw, user_id)); conn.commit()
        if cursor.rowcount > 0: return True, "Senha alterada!"
        else: return False, "Usuário não encontrado."
    except sqlite3.Error as e: return False, f"Erro ao alterar senha."
    finally:
        if conn: conn.close()

# --- NOVA: Função Admin para Resetar Senha ---
def admin_reset_user_password(username_to_reset, new_password):
    """Admin reseta a senha de outro usuário (não-admin)."""
    conn = get_db_connection();
    if not conn: return False, "Erro DB."
    if not new_password or len(new_password) < 4: return False, "Nova senha inválida (min 4 chars)."

    # Segurança: Verifica se o usuário a resetar *não* é admin
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT is_admin FROM users WHERE username = ? COLLATE NOCASE", (username_to_reset,))
        target_user = cursor.fetchone()
        if not target_user: return False, "Usuário alvo não encontrado."
        if target_user['is_admin']: return False, "Não é possível resetar a senha de outro administrador."

        # Procede com o reset
        sql_update = "UPDATE users SET password_hash = ? WHERE username = ? COLLATE NOCASE"
        new_hashed_pw = hash_password(new_password)
        cursor.execute(sql_update, (new_hashed_pw, username_to_reset))
        conn.commit()

        if cursor.rowcount > 0: return True, f"Senha do usuário '{username_to_reset}' resetada com sucesso!"
        else: return False, "Falha ao resetar senha (usuário não encontrado após verificação)." # Pouco provável
    except sqlite3.Error as e:
        return False, f"Erro DB ao resetar senha: {e}"
    finally:
        if conn: conn.close()

# --- NOVA: Função Admin para Deletar Usuário ---
def delete_user_by_username(username_to_delete, current_admin_username):
    """Admin deleta outro usuário (não-admin e não a si mesmo)."""
    conn = get_db_connection();
    if not conn: return False, "Erro DB."

    # Normaliza para comparação segura
    user_to_delete_lower = username_to_delete.lower()
    admin_username_lower = current_admin_username.lower()

    # Segurança: Admin não pode se deletar
    if user_to_delete_lower == admin_username_lower:
        return False, "Você não pode excluir sua própria conta de administrador."

    try:
        cursor = conn.cursor()
        # Segurança: Verifica se o usuário alvo existe e *não* é admin
        cursor.execute("SELECT is_admin FROM users WHERE username = ? COLLATE NOCASE", (username_to_delete,))
        target_user = cursor.fetchone()
        if not target_user: return False, "Usuário alvo não encontrado."
        if target_user['is_admin']: return False, "Não é possível excluir outro administrador."

        # Procede com a exclusão (CASCADE deve cuidar das entradas se a FK estiver definida)
        sql_delete = "DELETE FROM users WHERE username = ? COLLATE NOCASE"
        cursor.execute(sql_delete, (username_to_delete,))
        conn.commit()

        if cursor.rowcount > 0: return True, f"Usuário '{username_to_delete}' excluído com sucesso!"
        else: return False, "Falha ao excluir usuário (não encontrado após verificação)." # Pouco provável

    except sqlite3.Error as e:
        return False, f"Erro DB ao excluir usuário: {e}"
    finally:
        if conn: conn.close()

def get_all_users():
    conn = get_db_connection();
    if not conn: return []
    users_list = []; sql = "SELECT id, username, is_admin FROM users ORDER BY username COLLATE NOCASE" # Pega o ID também
    try: cursor = conn.cursor(); cursor.execute(sql); results = cursor.fetchall(); users_list = [dict(row) for row in results]
    except sqlite3.Error as e: st.error(f"Erro ao buscar usuários: {e}")
    finally:
        if conn: conn.close()
    return users_list

# --- Funções de Entradas (Cole aqui as funções da v12: clean_tags, add_entry, count_entries, get_entries, get_all_tags, update_entry, delete_entry, get_all_entries_for_export) ---
# ... (Omitidas por brevidade, mas cole-as aqui) ...
def clean_tags(tag_string):
    if not tag_string: return ""
    tags = [tag.strip().lower() for tag in tag_string.split(',') if tag.strip()]
    tags = [re.sub(r'[^a-z0-9\-]', '', tag) for tag in tags]
    tags = sorted(list(set(filter(None, tags)))); return ",".join(tags)

def add_entry(content, tags_str, entry_date, mood, user_id):
    conn = get_db_connection();
    if not conn or user_id is None: return False
    success = False; sql = "INSERT INTO entries (created_at, updated_at, content, tags, mood, user_id) VALUES (?, ?, ?, ?, ?, ?)"
    try: cursor = conn.cursor(); now_time = datetime.now().time(); entry_datetime = datetime.combine(entry_date, now_time); entry_iso = entry_datetime.isoformat(); updated_iso = datetime.now().isoformat(); cleaned_tags = clean_tags(tags_str); mood_to_save = mood if mood else MOOD_OPTIONS[0]; cursor.execute(sql, (entry_iso, updated_iso, content, cleaned_tags, mood_to_save, user_id)); conn.commit(); st.sidebar.success(f"Entrada salva: {entry_date.strftime(DATE_ONLY_FORMAT)}!"); success = True
    except sqlite3.Error as e: st.sidebar.error(f"Erro ao salvar: {e}")
    finally:
        if conn: conn.close()
    return success

def count_entries(user_id, search_term="", tag_filter="", date_filter=None):
    conn = get_db_connection();
    if not conn or user_id is None: return 0
    count = 0; params = [user_id]; base_query = "SELECT COUNT(*) FROM entries WHERE user_id = ?"
    try: cursor = conn.cursor();
    except sqlite3.Error as e: st.error(f"Erro ao contar: {e}")
    else:
        try:
            if search_term: base_query += " AND (content LIKE ? OR tags LIKE ?)"; params.extend([f"%{search_term}%", f"%{search_term}%"])
            if tag_filter: base_query += " AND ',' || lower(tags) || ',' LIKE ?"; params.append(f"%,{tag_filter.lower()},%")
            if date_filter: base_query += " AND DATE(created_at) = DATE(?)"; params.append(date_filter.isoformat())
            cursor.execute(base_query, tuple(params)); result = cursor.fetchone()
            if result: count = result[0]
        except sqlite3.Error as e: st.error(f"Erro query contar: {e}")
    finally:
        if conn: conn.close()
    return count

def get_entries(user_id, search_term="", tag_filter="", date_filter=None, page=1, limit=ITEMS_PER_PAGE):
    conn = get_db_connection();
    if not conn or user_id is None: return []
    entries = []; offset = (page - 1) * limit; params = [user_id]
    base_query = "SELECT id, created_at, updated_at, content, tags, mood FROM entries WHERE user_id = ?"
    try: cursor = conn.cursor();
    except sqlite3.Error as e: st.error(f"Erro ao buscar: {e}")
    else:
        try:
            if search_term: base_query += " AND (content LIKE ? OR tags LIKE ?)"; params.extend([f"%{search_term}%", f"%{search_term}%"])
            if tag_filter: base_query += " AND ',' || lower(tags) || ',' LIKE ?"; params.append(f"%,{tag_filter.lower()},%")
            if date_filter: base_query += " AND DATE(created_at) = DATE(?)"; params.append(date_filter.isoformat())
            base_query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"; params.extend([limit, offset])
            cursor.execute(base_query, tuple(params)); entries = cursor.fetchall()
        except sqlite3.Error as e: st.error(f"Erro query buscar: {e}")
    finally:
        if conn: conn.close()
    return entries

def get_all_tags(user_id):
    conn = get_db_connection();
    if not conn or user_id is None: return []
    all_tags_flat = []; sql = "SELECT tags FROM entries WHERE user_id = ? AND tags IS NOT NULL AND tags != ''"
    try: cursor = conn.cursor(); cursor.execute(sql, (user_id,)); results = cursor.fetchall()
    except sqlite3.Error as e: st.sidebar.warning(f"Erro tags: {e}")
    else:
        for row in results: all_tags_flat.extend([tag.strip() for tag in row['tags'].split(',') if tag.strip()])
    finally:
        if conn: conn.close()
    unique_tags = sorted(list(set(filter(None, all_tags_flat)))); return unique_tags

def update_entry(entry_id, new_content, new_tags_str, new_mood, user_id):
    conn = get_db_connection();
    if not conn or user_id is None: return False
    success = False; updated_iso = datetime.now().isoformat()
    sql = "UPDATE entries SET content = ?, tags = ?, mood = ?, updated_at = ? WHERE id = ? AND user_id = ?"
    try: cursor = conn.cursor(); cleaned_tags = clean_tags(new_tags_str); mood_to_save = new_mood if new_mood else MOOD_OPTIONS[0]; cursor.execute(sql, (new_content, cleaned_tags, mood_to_save, updated_iso, entry_id, user_id)); conn.commit()
    except sqlite3.Error as e: st.error(f"Erro ao atualizar: {e}")
    else:
        if cursor.rowcount > 0: st.success("Entrada atualizada!"); success = True
        else: st.warning(f"Entrada não encontrada/pertence.")
    finally:
        if conn: conn.close()
    return success

def delete_entry(entry_id, user_id):
    conn = get_db_connection();
    if not conn or user_id is None: return False
    success = False; sql = "DELETE FROM entries WHERE id = ? AND user_id = ?"
    try: cursor = conn.cursor(); cursor.execute(sql, (entry_id, user_id)); conn.commit()
    except sqlite3.Error as e: st.error(f"Erro ao excluir: {e}")
    else:
        if cursor.rowcount > 0: st.success("Entrada excluída!"); success = True
        else: st.warning(f"Entrada não encontrada/pertence.")
    finally:
        if conn: conn.close()
    return success

def get_all_entries_for_export(user_id):
    conn = get_db_connection();
    if not conn or user_id is None: return []
    entries_list_of_dicts = []; sql = "SELECT id, created_at, updated_at, content, tags, mood FROM entries WHERE user_id = ? ORDER BY created_at DESC"
    try: cursor = conn.cursor(); cursor.execute(sql, (user_id,)); results = cursor.fetchall(); entries_list_of_dicts = [dict(row) for row in results]
    except sqlite3.Error as e: st.error(f"Erro export: {e}")
    finally:
        if conn: conn.close()
    return entries_list_of_dicts


# --- Inicialização do Banco de Dados ---
init_db()

# --- Inicialização do Estado da Sessão ---
if 'logged_in' not in st.session_state: st.session_state.logged_in = False
if 'username' not in st.session_state: st.session_state.username = None
if 'user_id' not in st.session_state: st.session_state.user_id = None
if 'is_admin' not in st.session_state: st.session_state.is_admin = False
if 'auth_view' not in st.session_state: st.session_state.auth_view = "Login"
# ... (resto dos estados) ...
if 'login_attempt_failed' not in st.session_state: st.session_state.login_attempt_failed = False
if 'editing_id' not in st.session_state: st.session_state.editing_id = None
if 'entry_to_edit_content' not in st.session_state: st.session_state.entry_to_edit_content = ""
if 'entry_to_edit_tags' not in st.session_state: st.session_state.entry_to_edit_tags = ""
if 'entry_to_edit_mood' not in st.session_state: st.session_state.entry_to_edit_mood = MOOD_OPTIONS[0]
if 'confirming_delete_id' not in st.session_state: st.session_state.confirming_delete_id = None
if 'search_query' not in st.session_state: st.session_state.search_query = ""
if 'tag_filter' not in st.session_state: st.session_state.tag_filter = "-- Todas --"
if 'selected_date_for_entry' not in st.session_state: st.session_state.selected_date_for_entry = datetime.now().date()
if 'filter_by_date' not in st.session_state: st.session_state.filter_by_date = None
if 'current_page' not in st.session_state: st.session_state.current_page = 1
# --- NOVOS ESTADOS ADMIN ---
if 'admin_action_user' not in st.session_state: st.session_state.admin_action_user = None # Guarda username alvo da ação
if 'admin_confirm_delete' not in st.session_state: st.session_state.admin_confirm_delete = False
if 'admin_reset_pw_form' not in st.session_state: st.session_state.admin_reset_pw_form = False

# --- Função UI: Tela de Autenticação (Igual) ---
def display_auth_page():
    st.set_page_config(page_title="Acesso ao Diário", layout="centered")
    st.title("Bem-vindo ao Diário Pessoal")
    current_auth_view = st.session_state.auth_view
    auth_option = st.radio("Selecione:", ('Login', 'Registrar'), key='auth_option_radio', horizontal=True, index=0 if current_auth_view == "Login" else 1)
    if auth_option != current_auth_view: st.session_state.auth_view = auth_option; st.session_state.login_attempt_failed = False; st.rerun()

    if st.session_state.auth_view == "Login":
        st.subheader("Login")
        login_error_placeholder = st.empty()
        if 'login_user_input' not in st.session_state: st.session_state.login_user_input = ""
        if 'login_pass_input' not in st.session_state: st.session_state.login_pass_input = ""
        with st.form("login_form_key"):
            login_username = st.text_input("Usuário", key="login_user_key_persist", value=st.session_state.login_user_input).strip()
            login_password = st.text_input("Senha", type="password", key="login_pass_key_persist", value=st.session_state.login_pass_input)
            login_button = st.form_submit_button("Entrar")
            if login_button:
                st.session_state.login_user_input = login_username; st.session_state.login_pass_input = login_password; st.session_state.login_attempt_failed = False
                if not login_username or not login_password: st.warning("Preencha usuário e senha.")
                else:
                    login_success, user_id, is_admin = verify_user(login_username, login_password)
                    if login_success:
                        st.session_state.logged_in = True; st.session_state.username = login_username.lower(); st.session_state.user_id = user_id; st.session_state.is_admin = is_admin
                        st.session_state.login_user_input = ""; st.session_state.login_pass_input = ""; st.rerun()
                    else:
                        st.session_state.login_attempt_failed = True; st.session_state.login_pass_input = ""; st.rerun()
        if st.session_state.login_attempt_failed:
            login_error_placeholder.error("Usuário ou senha inválidos.")
            if st.button("Registrar Novo Usuário?", key="suggest_register_btn_after_fail"):
                st.session_state.auth_view = "Registrar"; st.session_state.login_attempt_failed = False; st.session_state.login_user_input = ""; st.session_state.login_pass_input = ""; st.rerun()

    elif st.session_state.auth_view == "Registrar":
         st.subheader("Registrar Novo Usuário")
         with st.form("register_form_key"):
             reg_username = st.text_input("Nome de usuário", key="reg_user_key").strip()
             reg_password = st.text_input("Senha", type="password", key="reg_pass_key")
             reg_password_confirm = st.text_input("Confirme a senha", type="password", key="reg_pass_confirm_key")
             register_button = st.form_submit_button("Registrar")
             if register_button:
                 if not reg_username or not reg_password or not reg_password_confirm: st.warning("Preencha todos os campos.")
                 elif len(reg_password) < 4: st.warning("Senha muito curta (mínimo 4 caracteres).")
                 elif reg_password != reg_password_confirm: st.error("As senhas não coincidem.")
                 else:
                     success, message = add_user(reg_username, reg_password)
                     if success: st.success(message + " Faça o login agora."); st.session_state.auth_view = "Login"; st.rerun()
                     else: st.error(message)


# --- Função UI: Aplicação Principal do Diário ---
def display_diary_application():
    st.set_page_config(page_title=f"Diário de {st.session_state.username.capitalize()}", layout="wide")
    st.title(f"📖 Diário Pessoal de {st.session_state.username.capitalize()}")

    current_user_id = st.session_state.get('user_id')
    is_user_admin = st.session_state.get('is_admin', False)
    if current_user_id is None:
        st.error("Erro: ID do usuário. Login necessário."); st.session_state.logged_in = False; st.rerun(); return

    # --- Sidebar ---
    with st.sidebar:
        admin_badge = " (Admin)" if is_user_admin else ""
        st.write(f"Logado como: **{st.session_state.username}**{admin_badge}")
        if st.button("🔓 Sair / Logout"):
            keys_to_delete = [k for k in st.session_state.keys() if k != 'auth_view'];
            for key in keys_to_delete: del st.session_state[key]
            st.session_state.logged_in = False; st.rerun()
        st.divider()

        with st.expander("🔑 Alterar Minha Senha"): # Alterar própria senha
            with st.form("change_password_form", clear_on_submit=True):
                current_password = st.text_input("Senha Atual", type="password", key="chp_current_pw")
                new_password = st.text_input("Nova Senha", type="password", key="chp_new_pw")
                confirm_new_password = st.text_input("Confirmar Nova Senha", type="password", key="chp_confirm_new_pw")
                change_pw_button = st.form_submit_button("Alterar Senha")
                if change_pw_button:
                    if not current_password or not new_password or not confirm_new_password: st.warning("Preencha todos os campos.")
                    elif not verify_user(st.session_state.username, current_password)[0]: st.error("Senha atual incorreta.")
                    elif len(new_password) < 4: st.warning("Nova senha muito curta.")
                    elif new_password != confirm_new_password: st.error("Nova senha e confirmação não coincidem.")
                    else:
                        success, message = update_user_password(current_user_id, new_password)
                        if success: st.success(message)
                        else: st.error(message)
        st.divider()

        # --- Restante da Sidebar (Data, Nova Entrada, Filtros, Exportar) ---
        # ... (Código igual ao anterior para essas seções) ...
        st.header("🗓️ Data da Nova Entrada"); chosen_date = st.date_input("Selecione a data:", value=st.session_state.selected_date_for_entry, key="date_selector_new_entry")
        if chosen_date != st.session_state.selected_date_for_entry: st.session_state.selected_date_for_entry = chosen_date; st.rerun()
        st.caption(f"Escrevendo para: **{st.session_state.selected_date_for_entry.strftime(DATE_ONLY_FORMAT)}**"); st.divider()
        st.header("✨ Nova Entrada")
        with st.form("new_entry_form", clear_on_submit=True):
            new_content = st.text_area("O que aconteceu?", height=150, key="new_content_area")
            new_tags = st.text_input("Tags (vírgula)", key="new_tags_input")
            new_mood = st.radio("Humor:", MOOD_OPTIONS, key="new_mood_radio", horizontal=True, index=0)
            submitted_new = st.form_submit_button(f"💾 Salvar")
            if submitted_new:
                if new_content:
                    if add_entry(new_content, new_tags, st.session_state.selected_date_for_entry, new_mood, current_user_id): st.session_state.current_page = 1; st.rerun()
                else: st.warning("Entrada vazia.")
        st.divider()
        st.header("🔍 Pesquisar / Filtrar"); search_input = st.text_input("Pesquisar", value=st.session_state.search_query, key="search_input_key")
        if search_input != st.session_state.search_query: st.session_state.search_query = search_input; st.session_state.current_page = 1; st.rerun()
        available_tags = get_all_tags(current_user_id)
        tag_selection = st.selectbox("Tag", ["-- Todas --"] + available_tags, index=0, key="tag_filter_select")
        if tag_selection != st.session_state.tag_filter: st.session_state.tag_filter = tag_selection; st.session_state.current_page = 1; st.rerun()
        filter_date_active = st.checkbox("Data específica?", key="date_filter_active_key", value=(st.session_state.filter_by_date is not None))
        if filter_date_active:
            date_val = st.session_state.filter_by_date if st.session_state.filter_by_date else datetime.now().date()
            selected_filter_date_val = st.date_input("Mostrar de:", value=date_val, key="date_filter_selector_key")
            if selected_filter_date_val != st.session_state.filter_by_date: st.session_state.filter_by_date = selected_filter_date_val; st.session_state.current_page = 1; st.rerun()
        elif st.session_state.filter_by_date is not None: st.session_state.filter_by_date = None; st.session_state.current_page = 1; st.rerun()
        if st.button("Limpar Filtros"): st.session_state.search_query = ""; st.session_state.tag_filter = "-- Todas --"; st.session_state.filter_by_date = None; st.session_state.current_page = 1; st.rerun()
        st.divider()
        st.header("⚙️ Ações");
        # Backup Local
        if st.button("💾 Backup DB Local", key="backup_db_button_local"):
            if os.path.exists(DB_FILE):
                 try: backup_dir = "backups_diario_local"; os.makedirs(backup_dir, exist_ok=True); ts = datetime.now().strftime("%Y%m%d_%H%M%S"); bf = os.path.join(backup_dir, f"{os.path.basename(DB_FILE)}_backup_{ts}.db"); shutil.copy2(DB_FILE, bf); st.success(f"Backup local: {bf}")
                 except Exception as e: st.error(f"Erro backup local: {e}")
            else: st.warning("Arquivo DB local não encontrado.")

        st.subheader("Exportar Minhas Entradas")
        col_export1, col_export2 = st.columns(2)
        all_entries_export = get_all_entries_for_export(current_user_id)
        if not all_entries_export: st.caption("Nada a exportar.")
        else:
            df_export = pd.DataFrame(all_entries_export); df_export = df_export[['id', 'created_at', 'updated_at', 'content', 'tags', 'mood']]
            with col_export1:
                try: csv_data = df_export.to_csv(index=False, encoding='utf-8'); st.download_button("📄 CSV", csv_data, f"diario_{st.session_state.username}_exp_{datetime.now().strftime('%Y%m%d')}.csv", 'text/csv', key='csv_key')
                except Exception as e: st.error(f"Erro CSV: {e}")
            with col_export2:
                try: json_data = df_export.to_json(orient='records', indent=4, force_ascii=False); st.download_button("📑 JSON", json_data, f"diario_{st.session_state.username}_exp_{datetime.now().strftime('%Y%m%d')}.json", 'application/json', key='json_key')
                except Exception as e: st.error(f"Erro JSON: {e}")


        # --- PAINEL ADMIN ---
        if is_user_admin:
            st.divider()
            st.header("👑 Painel Administrador")
            admin_expander = st.expander("Gerenciar Usuários", expanded=False)
            with admin_expander:
                all_users = get_all_users()
                admin_action_placeholder = st.empty() # Para mensagens de erro/sucesso das ações admin

                if not all_users:
                    st.write("Nenhum usuário encontrado.")
                else:
                    # Usar colunas para layout da lista de usuários
                    cols = st.columns((3, 1, 1, 1)) # Colunas: User | Admin? | Reset | Delete
                    cols[0].markdown("**Usuário**")
                    cols[1].markdown("**Admin?**")
                    cols[2].markdown("**Resetar**")
                    cols[3].markdown("**Excluir**")

                    for user in all_users:
                        user_username = user['username']
                        user_is_admin = bool(user['is_admin'])
                        is_self = (user_username.lower() == st.session_state.username.lower())

                        cols = st.columns((3, 1, 1, 1))
                        cols[0].write(user_username)
                        cols[1].write("✔️" if user_is_admin else "❌")

                        # Botões de ação só aparecem para outros usuários NÃO admins
                        if not is_self and not user_is_admin:
                            # Botão Resetar Senha
                            reset_btn_key = f"reset_pw_{user_username}"
                            if cols[2].button("🔑", key=reset_btn_key, help=f"Resetar senha de {user_username}"):
                                st.session_state.admin_action_user = user_username
                                st.session_state.admin_reset_pw_form = True
                                st.session_state.admin_confirm_delete = False # Garante que só uma ação por vez
                                st.rerun() # Mostra o formulário de reset

                            # Botão Excluir Usuário
                            delete_btn_key = f"delete_user_{user_username}"
                            if cols[3].button("🗑️", key=delete_btn_key, help=f"Excluir {user_username}"):
                                st.session_state.admin_action_user = user_username
                                st.session_state.admin_confirm_delete = True
                                st.session_state.admin_reset_pw_form = False # Garante que só uma ação por vez
                                st.rerun() # Mostra a confirmação de delete
                        else:
                            # Espaços vazios ou traços para admin/próprio usuário
                            cols[2].write("-")
                            cols[3].write("-")

                    st.divider()

                    # --- Formulário de Reset de Senha (Condicional) ---
                    if st.session_state.get('admin_reset_pw_form') and st.session_state.get('admin_action_user'):
                        target_user = st.session_state.admin_action_user
                        with st.form(f"reset_pw_form_{target_user}", clear_on_submit=True):
                            st.markdown(f"**Resetar Senha para:** `{target_user}`")
                            admin_new_pw = st.text_input("Nova Senha", type="password", key=f"admin_new_pw_{target_user}")
                            admin_confirm_pw = st.text_input("Confirmar Nova Senha", type="password", key=f"admin_confirm_pw_{target_user}")
                            col_reset1, col_reset2, _ = st.columns([1,1,3])
                            with col_reset1:
                                submit_reset = st.form_submit_button("✔️ Resetar")
                            with col_reset2:
                                cancel_reset = st.form_submit_button("❌ Cancelar")

                            if submit_reset:
                                if not admin_new_pw or not admin_confirm_pw: st.warning("Preencha ambos os campos.")
                                elif len(admin_new_pw) < 4: st.warning("Senha muito curta.")
                                elif admin_new_pw != admin_confirm_pw: st.error("Senhas não coincidem.")
                                else:
                                    success, message = admin_reset_user_password(target_user, admin_new_pw)
                                    if success: admin_action_placeholder.success(message)
                                    else: admin_action_placeholder.error(message)
                                    # Limpa estado para esconder o form
                                    st.session_state.admin_action_user = None
                                    st.session_state.admin_reset_pw_form = False
                                    st.rerun() # Recarrega a lista de usuários/mensagens
                            if cancel_reset:
                                st.session_state.admin_action_user = None
                                st.session_state.admin_reset_pw_form = False
                                st.rerun()

                    # --- Confirmação de Exclusão de Usuário (Condicional) ---
                    if st.session_state.get('admin_confirm_delete') and st.session_state.get('admin_action_user'):
                        target_user = st.session_state.admin_action_user
                        st.warning(f"Tem certeza que deseja excluir o usuário `{target_user}`? Todas as suas entradas serão perdidas (se a FK CASCADE estiver ativa).")
                        col_del1, col_del2, _ = st.columns([1, 1, 3])
                        with col_del1:
                            if st.button("✔️ Sim, Excluir", key=f"confirm_delete_user_{target_user}"):
                                success, message = delete_user_by_username(target_user, st.session_state.username)
                                if success: admin_action_placeholder.success(message)
                                else: admin_action_placeholder.error(message)
                                # Limpa estado para esconder a confirmação
                                st.session_state.admin_action_user = None
                                st.session_state.admin_confirm_delete = False
                                st.rerun() # Recarrega a lista de usuários/mensagens
                        with col_del2:
                            if st.button("❌ Não, Cancelar", key=f"cancel_delete_user_{target_user}"):
                                st.session_state.admin_action_user = None
                                st.session_state.admin_confirm_delete = False
                                st.rerun()


        st.divider(); st.caption(f"Diário v13.0 | SQLite Admin") # Atualizar versão


    # --- Área Principal (Lógica de exibição/edição/delete/paginação igual) ---
    st.header("🗓️ Minhas Entradas")
    if st.session_state.filter_by_date: st.subheader(f"Mostrando de: {st.session_state.filter_by_date.strftime(DATE_ONLY_FORMAT)}")
    current_tag_filter_val = "" if st.session_state.tag_filter == "-- Todas --" else st.session_state.tag_filter
    total_items = count_entries(current_user_id, st.session_state.search_query, current_tag_filter_val, st.session_state.filter_by_date)
    total_pages = math.ceil(total_items / ITEMS_PER_PAGE) if total_items > 0 else 1
    if st.session_state.current_page > total_pages: st.session_state.current_page = max(1, total_pages)
    paginated_entries = get_entries(current_user_id, st.session_state.search_query, current_tag_filter_val, st.session_state.filter_by_date, st.session_state.current_page, ITEMS_PER_PAGE)

    if not paginated_entries: st.info("Nenhuma entrada sua encontrada.")
    else:
        for entry in paginated_entries:
            entry_id = entry['id']; is_editing = (st.session_state.editing_id == entry_id); is_confirming_delete = (st.session_state.confirming_delete_id == entry_id)
            try: created_dt = datetime.fromisoformat(entry['created_at']) if entry['created_at'] else None; updated_dt = datetime.fromisoformat(entry['updated_at']) if entry['updated_at'] else None; created_time_str = created_dt.strftime(DATE_FORMAT) if created_dt else "N/A"; updated_time_str = updated_dt.strftime(DATE_FORMAT) if updated_dt else "N/A"
            except (TypeError, ValueError): created_time_str = "Inválida"; updated_time_str = "Inválida"
            tags_list = [t.strip() for t in entry['tags'].split(',') if t.strip()] if entry['tags'] else []
            current_mood = entry['mood'] if entry['mood'] else MOOD_OPTIONS[0]
            with st.container(border=True):
                col_meta1, col_meta2 = st.columns([8,1])
                with col_meta1:
                    st.caption(f"Criado: {created_time_str} | Atualizado: {updated_time_str} | ID: {entry_id}")
                    if tags_list: tag_display = " ".join([f"`{tag}`" for tag in tags_list]); st.markdown(f"**Tags:** {tag_display}")
                with col_meta2: st.markdown(f"<div style='text-align: right; font-size: 1.5em;'>{current_mood}</div>", unsafe_allow_html=True)
                st.divider()
                if is_editing:
                    with st.form(f"edit_form_{entry_id}"):
                        edited_content = st.text_area("✍️ Editando:", value=st.session_state.entry_to_edit_content, height=150, key=f"edit_content_{entry_id}")
                        edited_tags = st.text_input("🏷️ Tags:", value=st.session_state.entry_to_edit_tags, key=f"edit_tags_{entry_id}")
                        try: mood_index = MOOD_OPTIONS.index(st.session_state.entry_to_edit_mood)
                        except ValueError: mood_index = 0
                        edited_mood = st.radio("Humor:", MOOD_OPTIONS, key=f"edit_mood_{entry_id}", horizontal=True, index=mood_index)
                        submitted_edit = st.form_submit_button("💾 Salvar")
                        if submitted_edit:
                            if update_entry(entry_id, edited_content, edited_tags, edited_mood, current_user_id): st.session_state.editing_id = None; st.session_state.entry_to_edit_content = ""; st.session_state.entry_to_edit_tags = ""; st.session_state.entry_to_edit_mood = MOOD_OPTIONS[0]; st.rerun()
                    if st.button("❌ Cancelar", key=f"cancel_edit_{entry_id}"): st.session_state.editing_id = None; st.session_state.entry_to_edit_content = ""; st.session_state.entry_to_edit_tags = ""; st.session_state.entry_to_edit_mood = MOOD_OPTIONS[0]; st.rerun()
                else:
                    st.markdown(entry['content'], unsafe_allow_html=False)
                    action_cols = st.columns(10)
                    with action_cols[0]:
                        if st.button("✏️", key=f"edit_{entry_id}", help="Editar"): st.session_state.editing_id = entry_id; st.session_state.entry_to_edit_content = entry['content']; st.session_state.entry_to_edit_tags = entry['tags'] if entry['tags'] else ""; st.session_state.entry_to_edit_mood = current_mood; st.session_state.confirming_delete_id = None; st.rerun()
                    with action_cols[1]:
                        if st.button("🗑️", key=f"delete_{entry_id}", help="Excluir"): st.session_state.confirming_delete_id = entry_id; st.session_state.editing_id = None; st.rerun()
                    if is_confirming_delete:
                        with action_cols[2]: st.warning("Excluir?")
                        with action_cols[3]:
                            if st.button("✔️", key=f"confirm_delete_{entry_id}", help="Sim"):
                                if delete_entry(entry_id, current_user_id): st.session_state.confirming_delete_id = None; new_total_items = count_entries(current_user_id, st.session_state.search_query, current_tag_filter_val, st.session_state.filter_by_date); new_total_pages = math.ceil(new_total_items/ITEMS_PER_PAGE) if new_total_items > 0 else 1;
                                if st.session_state.current_page > new_total_pages: st.session_state.current_page = max(1, new_total_pages); st.rerun()
                        with action_cols[4]:
                            if st.button("❌", key=f"cancel_delete_{entry_id}", help="Não"): st.session_state.confirming_delete_id = None; st.rerun()
        st.divider()
        if total_pages > 1: # Paginação
            page_cols = st.columns([4, 1, 1]);
            with page_cols[0]: st.caption(f"Página {st.session_state.current_page}/{total_pages} ({total_items} entradas)")
            with page_cols[1]:
                if st.button("⬅️ Ant", key="prev_page", disabled=(st.session_state.current_page <= 1)): st.session_state.current_page -= 1; st.rerun()
            with page_cols[2]:
                if st.button("Próx ➡️", key="next_page", disabled=(st.session_state.current_page >= total_pages)): st.session_state.current_page += 1; st.rerun()


# --- Controle Principal da Aplicação ---
if st.session_state.logged_in:
    display_diary_application()
else:
    display_auth_page()