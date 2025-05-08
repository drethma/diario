# -*- coding: utf-8 -*-
import streamlit as st
import sqlite3 # Driver para SQLite
from datetime import datetime, time
import re
import os
import shutil # Para backup local
import pandas as pd
import math
import hashlib # Para hashing de senha

# --- Configurações Globais ---
DB_FILE = "meu_diario_local_completo.db" # Nome do arquivo do banco de dados local
DATE_FORMAT = "%d/%m/%Y %H:%M:%S"
DATE_ONLY_FORMAT = "%d/%m/%Y"
ITEMS_PER_PAGE = 5
MOOD_OPTIONS = ("❔", "😊", "😃", "🙂", "😐", "🙁", "😢", "😠", "🎉", "🤔")

# --- Funções Utilitárias ---
def hash_password(password):
  """Gera um hash SHA-256 para a senha."""
  return hashlib.sha256(password.encode()).hexdigest()

# --- Funções de Banco de Dados (SQLite) ---

def get_db_connection():
    """Estabelece conexão com o banco de dados SQLite local."""
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row # Retorna linhas como dicionários
        # Habilitar chaves estrangeiras (bom para integridade)
        conn.execute("PRAGMA foreign_keys = ON")
        return conn
    except sqlite3.Error as e:
        st.error(f"Erro crítico ao conectar ao banco de dados SQLite: {e}")
        return None

def init_db():
    """Inicializa o banco de dados, criando as tabelas se não existirem."""
    conn = get_db_connection()
    if not conn: st.stop()
    try:
        with conn: # Usar 'with conn' garante commit ou rollback
            cursor = conn.cursor()
            # Tabela de Usuários (com username case-insensitive)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    inserted_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            # Tabela de Entradas (com chave estrangeira para usuário)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL, -- Chave estrangeira
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    content TEXT NOT NULL,
                    tags TEXT,
                    mood TEXT,
                    inserted_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE -- Deleta entradas se usuário for deletado
                )
            ''')
            # Adicionar coluna mood se não existir (para compatibilidade)
            cursor.execute("PRAGMA table_info(entries)")
            columns = [column['name'] for column in cursor.fetchall()]
            if 'mood' not in columns:
                st.warning("Atualizando BD: Adicionando coluna 'mood'.")
                cursor.execute("ALTER TABLE entries ADD COLUMN mood TEXT DEFAULT ?", (MOOD_OPTIONS[0],))

            # Índices (Opcional, mas bom para performance)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_entries_user_created ON entries (user_id, created_at DESC);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_entries_tags ON entries (tags);") # Índice simples para tags
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users (username);") # Índice único já coberto por UNIQUE constraint

    except sqlite3.Error as e:
        st.error(f"Erro ao inicializar tabelas: {e}")
        st.stop()
    # Não precisa fechar a conexão explicitamente com 'with conn'

def add_user(username, password):
    """Adiciona um novo usuário."""
    conn = get_db_connection()
    if not conn: return False, "Erro de conexão."
    if not username or not username.strip(): return False, "Usuário vazio."
    sql = "INSERT INTO users (username, password_hash) VALUES (?, ?)" # Placeholder ?
    try:
        with conn:
            hashed_pw = hash_password(password)
            conn.execute(sql, (username.strip(), hashed_pw)) # Não precisa mais de .lower() devido a COLLATE NOCASE
        return True, "Usuário registrado!"
    except sqlite3.IntegrityError: # Erro de violação UNIQUE
        return False, "Nome de usuário já existe."
    except sqlite3.Error as e:
        return False, f"Erro ao registrar: {e}"

def verify_user(username, password):
    """Verifica credenciais e retorna (True/False, user_id)."""
    conn = get_db_connection()
    if not conn: return False, None
    sql = "SELECT id, password_hash FROM users WHERE username = ?" # Placeholder ?
    user_id = None
    is_valid = False
    try:
        cursor = conn.cursor()
        cursor.execute(sql, (username,))
        result = cursor.fetchone()
        if result:
            stored_hash = result['password_hash']
            entered_hash = hash_password(password)
            if stored_hash == entered_hash:
                is_valid = True
                user_id = result['id']
    except sqlite3.Error as e:
        st.error(f"Erro verificação: {e}")
    finally:
        if conn: conn.close()
    return is_valid, user_id

def update_user_password(user_id, new_password_hash):
    """Atualiza o hash da senha para um user_id."""
    conn = get_db_connection()
    if not conn: return False, "Erro de conexão."
    if user_id is None: return False, "ID do usuário inválido."
    sql = "UPDATE users SET password_hash = ? WHERE id = ?" # Placeholder ?
    success = False
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(sql, (new_password_hash, user_id))
            # rowcount é mais confiável após o commit do 'with'
            # Para verificar se funcionou, podemos tentar buscar o usuário de novo
            # mas por simplicidade, vamos assumir sucesso se não houver erro.
            success = True # Assumir sucesso se não houver exceção
    except sqlite3.Error as e:
        st.error(f"Erro ao atualizar senha: {e}")
        return False, f"Erro DB: {e}"
    finally:
        # 'with conn' fecha a conexão implicitamente em caso de erro,
        # mas fechar aqui é seguro também.
        if conn: conn.close()

    if success:
        # Precisamos verificar se a linha foi afetada. Requer consulta extra ou confiar na ausência de erro.
        # Vamos simplificar e retornar sucesso se não houve erro.
         return True, "Senha atualizada com sucesso!"

    else:
        # Se chegamos aqui, algo deu errado, mas não foi uma exceção SQL.
        # Isso é improvável com a lógica atual.
        return False, "Falha ao atualizar senha (causa desconhecida)."


def clean_tags(tag_string):
    # Sem mudanças
    if not tag_string: return ""
    tags = [tag.strip().lower() for tag in tag_string.split(',') if tag.strip()]
    tags = [re.sub(r'[^a-z0-9\-]', '', tag) for tag in tags]
    tags = sorted(list(set(filter(None, tags)))); return ",".join(tags)

def add_entry(content, tags_str, entry_date, mood, user_id):
    """Adiciona uma nova entrada de diário."""
    conn = get_db_connection()
    if not conn: return False
    if user_id is None: st.sidebar.error("Erro: Usuário não identificado."); return False
    success = False
    sql = "INSERT INTO entries (user_id, created_at, updated_at, content, tags, mood) VALUES (?, ?, ?, ?, ?, ?)" # Placeholder ?
    try:
        with conn:
            now_iso = datetime.now().isoformat() # Usar ISO para timestamps
            entry_datetime_iso = datetime.combine(entry_date, datetime.min.time()).isoformat() # Armazena data selecionada (sem hora específica aqui)
            cleaned_tags = clean_tags(tags_str)
            mood_to_save = mood if mood else MOOD_OPTIONS[0]
            # Usar entry_datetime_iso para created_at e now_iso para updated_at
            conn.execute(sql, (user_id, entry_datetime_iso, now_iso, content, cleaned_tags, mood_to_save))
        st.sidebar.success(f"Entrada salva: {entry_date.strftime(DATE_ONLY_FORMAT)}!")
        success = True
    except sqlite3.Error as e:
        st.sidebar.error(f"Erro ao salvar entrada: {e}")
    return success # 'with conn' já fechou a conexão se necessário

def count_entries(user_id, search_term="", tag_filter="", date_filter=None):
    """Conta entradas do usuário que correspondem aos filtros."""
    conn = get_db_connection()
    if not conn or user_id is None: return 0
    count = 0
    params = [user_id]
    base_query = "SELECT COUNT(*) FROM entries WHERE user_id = ?" # Placeholder ?
    try:
        if search_term:
            base_query += " AND (lower(content) LIKE lower(?) OR lower(tags) LIKE lower(?))" # lower() para case-insensitive
            params.extend([f"%{search_term}%", f"%{search_term}%"])
        if tag_filter:
            base_query += " AND ',' || lower(tags) || ',' LIKE ?" # lower()
            params.append(f"%,{tag_filter.lower()},%")
        if date_filter:
            # Comparar datas no SQLite requer cuidado com o formato armazenado (ISO neste caso)
            # Usar DATE() funciona bem com formato YYYY-MM-DD ou ISO
            base_query += " AND DATE(created_at) = DATE(?)" # Usar DATE() em ambos
            params.append(entry_date.strftime('%Y-%m-%d')) # Formato para DATE()

        cursor = conn.cursor()
        cursor.execute(base_query, tuple(params))
        result = cursor.fetchone()
        if result: count = result[0]
    except sqlite3.Error as e:
        st.error(f"Erro ao contar entradas: {e}")
    finally:
        if conn: conn.close()
    return count

def get_entries(user_id, search_term="", tag_filter="", date_filter=None, page=1, limit=ITEMS_PER_PAGE):
    """Busca entradas do usuário com filtros e paginação."""
    conn = get_db_connection()
    if not conn or user_id is None: return []
    entries = []
    offset = (page - 1) * limit
    params = [user_id]
    base_query = "SELECT id, created_at, updated_at, content, tags, mood FROM entries WHERE user_id = ?" # Placeholder ?
    try:
        if search_term:
            base_query += " AND (lower(content) LIKE lower(?) OR lower(tags) LIKE lower(?))"
            params.extend([f"%{search_term}%", f"%{search_term}%"])
        if tag_filter:
            base_query += " AND ',' || lower(tags) || ',' LIKE ?"
            params.append(f"%,{tag_filter.lower()},%")
        if date_filter:
            base_query += " AND DATE(created_at) = DATE(?)"
            params.append(date_filter.strftime('%Y-%m-%d'))

        base_query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor = conn.cursor()
        cursor.execute(base_query, tuple(params))
        entries = cursor.fetchall() # Retorna lista de sqlite3.Row
    except sqlite3.Error as e:
        st.error(f"Erro ao buscar entradas: {e}")
    finally:
        if conn: conn.close()
    return entries # Retorna lista de sqlite3.Row (dict-like)

def get_all_tags(user_id):
    """Busca todas as tags únicas do usuário."""
    conn = get_db_connection()
    if not conn or user_id is None: return []
    all_tags_flat = []
    sql = "SELECT tags FROM entries WHERE user_id = ? AND tags IS NOT NULL AND tags != ''" # Placeholder ?
    try:
        cursor = conn.cursor()
        cursor.execute(sql, (user_id,))
        results = cursor.fetchall()
        for row in results:
            all_tags_flat.extend([tag.strip() for tag in row['tags'].split(',') if tag.strip()])
    except sqlite3.Error as e:
        st.sidebar.warning(f"Erro tags: {e}")
    finally:
        if conn: conn.close()
    unique_tags = sorted(list(set(filter(None, all_tags_flat))))
    return unique_tags

def update_entry(entry_id, new_content, new_tags_str, new_mood, user_id):
    """Atualiza uma entrada existente."""
    conn = get_db_connection()
    if not conn or user_id is None: return False
    success = False
    sql = "UPDATE entries SET content = ?, tags = ?, mood = ?, updated_at = ? WHERE id = ? AND user_id = ?" # Placeholder ?
    try:
        with conn:
            now_iso = datetime.now().isoformat()
            cleaned_tags = clean_tags(new_tags_str)
            mood_to_save = new_mood if new_mood else MOOD_OPTIONS[0]
            cursor = conn.cursor()
            cursor.execute(sql, (new_content, cleaned_tags, mood_to_save, now_iso, entry_id, user_id))
            if cursor.rowcount > 0: st.success("Entrada atualizada!"); success = True
            else: st.warning(f"Entrada não encontrada ou não pertence a você.")
    except sqlite3.Error as e:
        st.error(f"Erro ao atualizar: {e}")
    # 'with conn' fecha a conexão
    return success

def delete_entry(entry_id, user_id):
    """Exclui uma entrada."""
    conn = get_db_connection()
    if not conn or user_id is None: return False
    success = False
    sql = "DELETE FROM entries WHERE id = ? AND user_id = ?" # Placeholder ?
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(sql, (entry_id, user_id))
            if cursor.rowcount > 0: st.success("Entrada excluída!"); success = True
            else: st.warning(f"Entrada não encontrada ou não pertence a você.")
    except sqlite3.Error as e:
        st.error(f"Erro ao excluir: {e}")
    # 'with conn' fecha a conexão
    return success

def get_all_entries_for_export(user_id):
    """Busca todas as entradas do usuário para exportação."""
    conn = get_db_connection()
    if not conn or user_id is None: return []
    entries_list_of_dicts = []
    sql = "SELECT id, created_at, updated_at, content, tags, mood FROM entries WHERE user_id = ? ORDER BY created_at DESC" # Placeholder ?
    try:
        cursor = conn.cursor()
        cursor.execute(sql, (user_id,))
        results = cursor.fetchall()
        # Converter sqlite3.Row para dict padrão explicitamente para Pandas
        entries_list_of_dicts = [dict(row) for row in results]
    except sqlite3.Error as e:
        st.error(f"Erro export: {e}")
    finally:
        if conn: conn.close()
    return entries_list_of_dicts

def backup_db():
    """Cria uma cópia de backup do arquivo de banco de dados local."""
    if not os.path.exists(DB_FILE):
        st.error("Arquivo de banco de dados não encontrado para backup.")
        return False
    try:
        backup_dir = "backups_diario"
        os.makedirs(backup_dir, exist_ok=True)
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = os.path.join(backup_dir, f"{os.path.splitext(os.path.basename(DB_FILE))[0]}_backup_{timestamp_str}.db")
        shutil.copy2(DB_FILE, backup_filename) # copy2 preserva metadados
        st.success(f"Backup criado: {backup_filename}")
        return True
    except Exception as e:
        st.error(f"Erro ao criar backup: {e}")
        return False

# --- Inicialização do Banco de Dados ---
init_db()

# --- Inicialização do Estado da Sessão ---
if 'logged_in' not in st.session_state: st.session_state.logged_in = False
if 'username' not in st.session_state: st.session_state.username = None
if 'user_id' not in st.session_state: st.session_state.user_id = None
if 'auth_view' not in st.session_state: st.session_state.auth_view = "Login"
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


# --- Função UI: Tela de Autenticação ---
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
                    login_success, user_id = verify_user(login_username, login_password)
                    if login_success:
                        st.session_state.logged_in = True; st.session_state.username = login_username.lower(); st.session_state.user_id = user_id; st.session_state.login_user_input = ""; st.session_state.login_pass_input = ""; st.rerun()
                    else: st.session_state.login_attempt_failed = True; st.session_state.login_pass_input = ""; st.rerun()
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
    if current_user_id is None: st.error("Erro: ID do usuário perdido. Faça login."); st.session_state.logged_in = False; st.rerun(); return

    # --- Sidebar ---
    with st.sidebar:
        st.write(f"Logado como: **{st.session_state.username}** (ID: {current_user_id})")
        if st.button("🔓 Sair / Logout"):
            keys_to_delete = [k for k in st.session_state.keys() if k != 'auth_view']; [st.session_state.pop(k) for k in keys_to_delete]; st.session_state.logged_in = False; st.rerun()
        st.divider()
        # Nova Entrada
        st.header("🗓️ Data da Nova Entrada"); chosen_date = st.date_input("Data:", value=st.session_state.selected_date_for_entry, key="date_selector_new_entry"); st.caption(f"Para: **{chosen_date.strftime(DATE_ONLY_FORMAT)}**"); st.divider()
        st.header("✨ Nova Entrada")
        with st.form("new_entry_form", clear_on_submit=True):
            new_content = st.text_area("O que aconteceu:", height=150, key="new_content_area")
            new_tags = st.text_input("Tags (vírgula):", placeholder="ex: trabalho", key="new_tags_input")
            new_mood = st.radio("Humor:", MOOD_OPTIONS, key="new_mood_radio", horizontal=True, index=0)
            submitted_new = st.form_submit_button(f"💾 Salvar para {chosen_date.strftime(DATE_ONLY_FORMAT)}")
            if submitted_new:
                if new_content:
                    if add_entry(new_content, new_tags, chosen_date, new_mood, current_user_id): st.session_state.current_page = 1; st.rerun()
                else: st.warning("Entrada vazia.")
        st.divider()
        # Filtros
        st.header("🔍 Pesquisar / Filtrar"); search_input = st.text_input("Pesquisar:", value=st.session_state.search_query, key="search_input_key")
        if search_input != st.session_state.search_query: st.session_state.search_query = search_input; st.session_state.current_page = 1; st.rerun()
        available_tags = get_all_tags(current_user_id)
        tag_selection = st.selectbox("Tag:", ["-- Todas --"] + available_tags, index=(["-- Todas --"]+available_tags).index(st.session_state.tag_filter) if st.session_state.tag_filter in ["-- Todas --"]+available_tags else 0, key="tag_filter_select")
        if tag_selection != st.session_state.tag_filter: st.session_state.tag_filter = tag_selection; st.session_state.current_page = 1; st.rerun()
        filter_date_active = st.checkbox("Data específica?", key="date_filter_act_key", value=(st.session_state.filter_by_date is not None))
        if filter_date_active:
            date_val = st.session_state.filter_by_date or datetime.now().date(); selected_filter_date_val = st.date_input("Mostrar de:", value=date_val, key="date_filter_sel_key")
            if selected_filter_date_val != st.session_state.filter_by_date: st.session_state.filter_by_date = selected_filter_date_val; st.session_state.current_page = 1; st.rerun()
        elif st.session_state.filter_by_date is not None: st.session_state.filter_by_date = None; st.session_state.current_page = 1; st.rerun()
        if st.button("Limpar Filtros"): st.session_state.search_query = ""; st.session_state.tag_filter = "-- Todas --"; st.session_state.filter_by_date = None; st.session_state.current_page = 1; st.rerun()
        st.divider()
        # Ações
        st.header("⚙️ Ações")
        if st.button("💾 Backup DB Local", key="backup_db_button", help=f"Cria cópia de {DB_FILE}"): backup_db()
        st.subheader("Exportar Minhas Entradas")
        col_export1, col_export2 = st.columns(2); all_entries_export = get_all_entries_for_export(current_user_id)
        if not all_entries_export: st.caption("Nada a exportar.")
        else:
            df_export = pd.DataFrame(all_entries_export); df_export = df_export[['id', 'created_at', 'updated_at', 'content', 'tags', 'mood']]
            ts_exp = datetime.now().strftime('%Y%m%d')
            with col_export1:
                try: csv_data = df_export.to_csv(index=False, encoding='utf-8'); st.download_button("📄 CSV", csv_data, f"diario_{st.session_state.username}_{ts_exp}.csv", 'text/csv', key='csv_key')
                except Exception as e: st.error(f"Erro CSV: {e}")
            with col_export2:
                try: json_data = df_export.to_json(orient='records', indent=4, force_ascii=False); st.download_button("📑 JSON", json_data, f"diario_{st.session_state.username}_{ts_exp}.json", 'application/json', key='json_key')
                except Exception as e: st.error(f"Erro JSON: {e}")
        st.divider()
        # Configurações do Perfil
        with st.expander("⚙️ Configurações do Perfil"):
            st.subheader("Mudar Senha")
            with st.form("change_password_form", clear_on_submit=True):
                current_password = st.text_input("Senha Atual", type="password", key="current_pw")
                new_password = st.text_input("Nova Senha", type="password", key="new_pw")
                confirm_new_password = st.text_input("Confirmar Nova Senha", type="password", key="confirm_new_pw")
                change_pw_button = st.form_submit_button("Salvar Nova Senha")
                if change_pw_button:
                    if not current_password or not new_password or not confirm_new_password: st.warning("Preencha todos os campos.")
                    elif new_password != confirm_new_password: st.error("Novas senhas não coincidem.")
                    elif len(new_password) < 4: st.warning("Nova senha muito curta.")
                    else:
                        verify_success, _ = verify_user(st.session_state.username, current_password)
                        if verify_success:
                            new_hashed_password = hash_password(new_password)
                            update_success, update_message = update_user_password(current_user_id, new_hashed_password)
                            if update_success: st.success(update_message)
                            else: st.error(update_message)
                        else: st.error("Senha atual incorreta.")
        # Rodapé Sidebar
        st.caption(f"Diário Local v1.0")

    # --- Área Principal ---
    st.header("🗓️ Minhas Entradas")
    if st.session_state.filter_by_date: st.subheader(f"Mostrando de: {st.session_state.filter_by_date.strftime(DATE_ONLY_FORMAT)}")
    current_tag_filter_val = "" if st.session_state.tag_filter == "-- Todas --" else st.session_state.tag_filter
    total_items = count_entries(current_user_id, st.session_state.search_query, current_tag_filter_val, st.session_state.filter_by_date)
    total_pages = math.ceil(total_items / ITEMS_PER_PAGE) if total_items > 0 else 1
    if st.session_state.current_page > total_pages: st.session_state.current_page = max(1, total_pages)
    paginated_entries = get_entries(current_user_id, st.session_state.search_query, current_tag_filter_val, st.session_state.filter_by_date, st.session_state.current_page, ITEMS_PER_PAGE)

    if not paginated_entries: st.info("Nenhuma entrada encontrada.")
    else:
        for entry in paginated_entries:
            entry_id = entry['id']; is_editing = (st.session_state.editing_id == entry_id); is_confirming_delete = (st.session_state.confirming_delete_id == entry_id)
            try: # Tentar formatar datas ISO armazenadas como texto
                created_dt = datetime.fromisoformat(entry['created_at']) if entry['created_at'] else None
                updated_dt = datetime.fromisoformat(entry['updated_at']) if entry['updated_at'] else None
                created_time_str = created_dt.strftime(DATE_FORMAT) if created_dt else "N/A"
                updated_time_str = updated_dt.strftime(DATE_FORMAT) if updated_dt else "N/A"
            except (ValueError, TypeError): created_time_str = entry['created_at'] or "Inválida"; updated_time_str = entry['updated_at'] or "Inválida"
            tags_list = [t.strip() for t in entry['tags'].split(',') if t.strip()] if entry['tags'] else []
            current_mood = entry['mood'] if entry['mood'] else MOOD_OPTIONS[0]
            with st.container(border=True):
                col_meta1, col_meta2 = st.columns([8,1])
                with col_meta1: st.caption(f"Criado: {created_time_str} | Atualizado: {updated_time_str} | ID: {entry_id}");
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
        if total_pages > 1:
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