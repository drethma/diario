# -*- coding: utf-8 -*-
import streamlit as st
import sqlite3
from datetime import datetime, time
import re
import os
import shutil
import pandas as pd
import math
import hashlib

# --- Configurações Globais ---
DB_FILE = "meu_diario_v10_fix.db" # Novo nome para indicar correção
DATE_FORMAT = "%d/%m/%Y %H:%M:%S"
DATE_ONLY_FORMAT = "%d/%m/%Y"
ITEMS_PER_PAGE = 5
MOOD_OPTIONS = ("❔", "😊", "😃", "🙂", "😐", "🙁", "😢", "😠", "🎉", "🤔")

# --- Funções Utilitárias ---
def hash_password(password):
  return hashlib.sha256(password.encode()).hexdigest()

# --- Funções de Banco de Dados ---
# (Cole aqui TODAS as funções DB da versão anterior:
#  get_db_connection, init_db, add_user, verify_user, clean_tags, add_entry,
#  count_entries, get_entries, get_all_tags, update_entry, delete_entry,
#  get_all_entries_for_export)
# ... (Omitidas por brevidade) ...
def get_db_connection():
    try: conn = sqlite3.connect(DB_FILE); conn.row_factory = sqlite3.Row; return conn
    except sqlite3.Error as e: st.error(f"Erro DB Conn: {e}"); return None

def init_db():
    conn = get_db_connection();
    if not conn: st.stop()
    try:
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS entries (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, content TEXT NOT NULL, tags TEXT, mood TEXT)')
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_entries_created_at ON entries (created_at);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_entries_tags ON entries (tags);")
        cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL COLLATE NOCASE, password_hash TEXT NOT NULL)')
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users (username);")
        cursor.execute("PRAGMA table_info(entries)"); columns = [column['name'] for column in cursor.fetchall()]
        if 'mood' not in columns: st.warning("Adicionando coluna 'mood'."); cursor.execute("ALTER TABLE entries ADD COLUMN mood TEXT")
        conn.commit()
    except sqlite3.Error as e: st.error(f"Erro init DB: {e}"); st.stop()
    finally:
        if conn: conn.close()

def add_user(username, password):
    conn = get_db_connection();
    if not conn: return False, "Erro DB."
    if not username or not username.strip(): return False, "Usuário vazio."
    try: cursor = conn.cursor(); hashed_pw = hash_password(password); cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username.strip(), hashed_pw)); conn.commit(); return True, "Usuário registrado!"
    except sqlite3.IntegrityError: return False, "Usuário já existe."
    except sqlite3.Error as e: return False, f"Erro registro: {e}"
    finally:
        if conn: conn.close()

def verify_user(username, password):
    conn = get_db_connection();
    if not conn: return False
    try: cursor = conn.cursor(); cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,)); result = cursor.fetchone();
    except sqlite3.Error as e: st.error(f"Erro verificação: {e}"); return False
    finally:
        if conn: conn.close()

    if not result: return False
    return result['password_hash'] == hash_password(password)

def clean_tags(tag_string):
    if not tag_string: return ""
    tags = [tag.strip().lower() for tag in tag_string.split(',') if tag.strip()]
    tags = [re.sub(r'[^a-z0-9\-]', '', tag) for tag in tags]
    tags = sorted(list(set(filter(None, tags)))); return ",".join(tags)

def add_entry(content, tags_str, entry_date, mood):
    conn = get_db_connection();
    if not conn: return False
    success = False
    try: cursor = conn.cursor(); now_time = datetime.now().time(); entry_datetime = datetime.combine(entry_date, now_time); entry_iso = entry_datetime.isoformat(); cleaned_tags = clean_tags(tags_str); mood_to_save = mood if mood else MOOD_OPTIONS[0]; cursor.execute("INSERT INTO entries (created_at, updated_at, content, tags, mood) VALUES (?, ?, ?, ?, ?)", (entry_iso, entry_iso, content, cleaned_tags, mood_to_save)); conn.commit(); st.sidebar.success(f"Entrada salva: {entry_date.strftime(DATE_ONLY_FORMAT)}!"); success = True
    except sqlite3.Error as e: st.sidebar.error(f"Erro ao salvar: {e}")
    finally:
        if conn: conn.close()
    return success

def count_entries(search_term="", tag_filter="", date_filter=None):
    conn = get_db_connection();
    if not conn: return 0
    count = 0
    try: cursor = conn.cursor(); query = "SELECT COUNT(*) FROM entries WHERE 1=1"; params = [];
    except sqlite3.Error as e: st.error(f"Erro ao contar: {e}")
    else:
        try:
            if search_term: query += " AND (content LIKE ? OR tags LIKE ?)"; params.extend([f"%{search_term}%", f"%{search_term}%"])
            if tag_filter: query += " AND (',' || tags || ',' LIKE ?)"; params.append(f"%,{tag_filter},%")
            if date_filter: query += " AND DATE(created_at) = ?"; params.append(date_filter.strftime('%Y-%m-%d'))
            cursor.execute(query, params); result = cursor.fetchone()
            if result: count = result[0]
        except sqlite3.Error as e: st.error(f"Erro query contar: {e}")
    finally:
        if conn: conn.close()
    return count

def get_entries(search_term="", tag_filter="", date_filter=None, page=1, limit=ITEMS_PER_PAGE):
    conn = get_db_connection();
    if not conn: return []
    entries = []; offset = (page - 1) * limit
    try: cursor = conn.cursor(); query = "SELECT id, created_at, updated_at, content, tags, mood FROM entries WHERE 1=1"; params = []
    except sqlite3.Error as e: st.error(f"Erro ao buscar: {e}")
    else:
        try:
            if search_term: query += " AND (content LIKE ? OR tags LIKE ?)"; params.extend([f"%{search_term}%", f"%{search_term}%"])
            if tag_filter: query += " AND (',' || tags || ',' LIKE ?)"; params.append(f"%,{tag_filter},%")
            if date_filter: query += " AND DATE(created_at) = ?"; params.append(date_filter.strftime('%Y-%m-%d'))
            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"; params.extend([limit, offset])
            cursor.execute(query, params); entries = cursor.fetchall()
        except sqlite3.Error as e: st.error(f"Erro query buscar: {e}")
    finally:
        if conn: conn.close()
    return entries

def get_all_tags():
    conn = get_db_connection();
    if not conn: return []
    all_tags_flat = []
    try: cursor = conn.cursor(); cursor.execute("SELECT tags FROM entries WHERE tags IS NOT NULL AND tags != ''"); results = cursor.fetchall()
    except sqlite3.Error as e: st.sidebar.warning(f"Erro tags: {e}")
    else:
        for row in results: all_tags_flat.extend([tag.strip() for tag in row['tags'].split(',') if tag.strip()])
    finally:
        if conn: conn.close()
    unique_tags = sorted(list(set(filter(None, all_tags_flat)))); return unique_tags

def update_entry(entry_id, new_content, new_tags_str, new_mood):
    conn = get_db_connection();
    if not conn: return False
    success = False
    try: cursor = conn.cursor(); now_iso = datetime.now().isoformat(); cleaned_tags = clean_tags(new_tags_str); mood_to_save = new_mood if new_mood else MOOD_OPTIONS[0]; cursor.execute("UPDATE entries SET content = ?, tags = ?, mood = ?, updated_at = ? WHERE id = ?", (new_content, cleaned_tags, mood_to_save, now_iso, entry_id)); conn.commit()
    except sqlite3.Error as e: st.error(f"Erro ao atualizar: {e}")
    else:
        if conn.total_changes > 0: st.success("Entrada atualizada!"); success = True
        else: st.warning(f"ID {entry_id} não encontrado.")
    finally:
        if conn: conn.close()
    return success

def delete_entry(entry_id):
    conn = get_db_connection();
    if not conn: return False
    success = False
    try: cursor = conn.cursor(); cursor.execute("DELETE FROM entries WHERE id = ?", (entry_id,)); conn.commit()
    except sqlite3.Error as e: st.error(f"Erro ao excluir: {e}")
    else:
        if conn.total_changes > 0: st.success("Entrada excluída!"); success = True
        else: st.warning(f"ID {entry_id} não encontrado.")
    finally:
        if conn: conn.close()
    return success

def get_all_entries_for_export():
    conn = get_db_connection();
    if not conn: return []
    entries = []
    try: cursor = conn.cursor(); query = "SELECT id, created_at, updated_at, content, tags, mood FROM entries ORDER BY created_at DESC"; cursor.execute(query); entries = [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e: st.error(f"Erro export: {e}")
    finally:
        if conn: conn.close()
    return entries


# --- Inicialização do Banco de Dados ---
init_db()

# --- Inicialização do Estado da Sessão ---
if 'logged_in' not in st.session_state: st.session_state.logged_in = False
if 'username' not in st.session_state: st.session_state.username = None
if 'auth_view' not in st.session_state: st.session_state.auth_view = "Login"
if 'login_attempt_failed' not in st.session_state: st.session_state.login_attempt_failed = False # Flag para erro de login
if 'editing_id' not in st.session_state: st.session_state.editing_id = None
# ... (resto dos estados iguais) ...
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

    # Resetar flag de falha se mudar de visão
    current_auth_view = st.session_state.auth_view
    auth_option = st.radio(
        "Selecione:", ('Login', 'Registrar'), key='auth_option_radio', horizontal=True,
        index=0 if current_auth_view == "Login" else 1
    )
    if auth_option != current_auth_view:
        st.session_state.auth_view = auth_option
        st.session_state.login_attempt_failed = False # Reseta flag ao mudar de aba
        st.rerun()


    if st.session_state.auth_view == "Login":
        st.subheader("Login")
        login_error_placeholder = st.empty() # Placeholder para mensagem de erro
        # Usar um estado para lembrar o que foi digitado mesmo após o erro
        if 'login_user_input' not in st.session_state: st.session_state.login_user_input = ""
        if 'login_pass_input' not in st.session_state: st.session_state.login_pass_input = ""

        with st.form("login_form_key"):
            # Usar valores do estado para persistir inputs após erro
            login_username = st.text_input("Usuário", key="login_user_key_persist", value=st.session_state.login_user_input).strip()
            login_password = st.text_input("Senha", type="password", key="login_pass_key_persist", value=st.session_state.login_pass_input)
            login_button = st.form_submit_button("Entrar")

            if login_button:
                # Atualizar estado com valores digitados
                st.session_state.login_user_input = login_username
                st.session_state.login_pass_input = login_password
                st.session_state.login_attempt_failed = False # Reseta flag antes de tentar

                if not login_username or not login_password:
                    st.warning("Preencha usuário e senha.")
                elif verify_user(login_username, login_password):
                    st.session_state.logged_in = True
                    st.session_state.username = login_username.lower()
                    # Limpa campos de input após sucesso
                    st.session_state.login_user_input = ""
                    st.session_state.login_pass_input = ""
                    st.rerun()
                else:
                    # Login Falhou
                    st.session_state.login_attempt_failed = True # Define a flag
                    # Limpa senha do input, mas mantém usuário
                    st.session_state.login_pass_input = ""
                    st.rerun() # Rerun para mostrar erro e botão fora do form

        # --- MOVIDO PARA FORA DO FORM ---
        # Mostrar erro e botão somente se a tentativa falhou
        if st.session_state.login_attempt_failed:
            login_error_placeholder.error("Usuário ou senha inválidos.")
            if st.button("Registrar Novo Usuário?", key="suggest_register_btn_after_fail"):
                st.session_state.auth_view = "Registrar"
                st.session_state.login_attempt_failed = False # Reseta a flag
                # Limpa campos de input ao mudar para registro
                st.session_state.login_user_input = ""
                st.session_state.login_pass_input = ""
                st.rerun()


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
# (Esta função permanece IGUAL à versão anterior - v9_mood)
def display_diary_application():
    st.set_page_config(page_title=f"Diário de {st.session_state.username.capitalize()}", layout="wide")
    st.title(f"📖 Diário Pessoal de {st.session_state.username.capitalize()}")

    # --- Sidebar ---
    with st.sidebar:
        st.write(f"Logado como: **{st.session_state.username}**")
        if st.button("🔓 Sair / Logout"): # Logout direto agora
            keys_to_delete = [k for k in st.session_state.keys() if k != 'auth_view']
            for key in keys_to_delete: del st.session_state[key]
            st.session_state.logged_in = False
            st.rerun()
        st.divider()
        st.header("🗓️ Data da Nova Entrada"); chosen_date = st.date_input("Selecione a data:", value=st.session_state.selected_date_for_entry, key="date_selector_new_entry")
        if chosen_date != st.session_state.selected_date_for_entry: st.session_state.selected_date_for_entry = chosen_date; st.rerun()
        st.caption(f"Escrevendo para: **{st.session_state.selected_date_for_entry.strftime(DATE_ONLY_FORMAT)}**"); st.divider()
        st.header("✨ Nova Entrada")
        with st.form("new_entry_form", clear_on_submit=True):
            new_content = st.text_area("O que aconteceu neste dia?", height=150, key="new_content_area")
            new_tags = st.text_input("Tags (vírgula)", placeholder="ex: trabalho, pessoal", key="new_tags_input")
            new_mood = st.radio("Humor:", MOOD_OPTIONS, key="new_mood_radio", horizontal=True, index=0)
            submitted_new = st.form_submit_button(f"💾 Salvar para {st.session_state.selected_date_for_entry.strftime(DATE_ONLY_FORMAT)}")
            if submitted_new:
                if new_content:
                    if add_entry(new_content, new_tags, st.session_state.selected_date_for_entry, new_mood): st.session_state.current_page = 1; st.rerun()
                else: st.warning("A entrada não pode estar vazia.")
        st.divider()
        st.header("🔍 Pesquisar / Filtrar"); search_input = st.text_input("Pesquisar", value=st.session_state.search_query, key="search_input_key")
        if search_input != st.session_state.search_query: st.session_state.search_query = search_input; st.session_state.current_page = 1; st.rerun()
        available_tags = get_all_tags()
        tag_selection = st.selectbox("Tag", ["-- Todas --"] + available_tags, index=(["-- Todas --"] + available_tags).index(st.session_state.tag_filter) if st.session_state.tag_filter in ["-- Todas --"] + available_tags else 0, key="tag_filter_select")
        if tag_selection != st.session_state.tag_filter: st.session_state.tag_filter = tag_selection; st.session_state.current_page = 1; st.rerun()
        filter_date_active = st.checkbox("Data específica?", key="date_filter_active_key", value=(st.session_state.filter_by_date is not None))
        selected_filter_date_val = None
        if filter_date_active:
            date_val = st.session_state.filter_by_date if st.session_state.filter_by_date else datetime.now().date()
            selected_filter_date_val = st.date_input("Mostrar de:", value=date_val, key="date_filter_selector_key")
            if selected_filter_date_val != st.session_state.filter_by_date: st.session_state.filter_by_date = selected_filter_date_val; st.session_state.current_page = 1; st.rerun()
        elif st.session_state.filter_by_date is not None: st.session_state.filter_by_date = None; st.session_state.current_page = 1; st.rerun()
        if st.button("Limpar Filtros"): st.session_state.search_query = ""; st.session_state.tag_filter = "-- Todas --"; st.session_state.filter_by_date = None; st.session_state.current_page = 1; st.rerun()
        st.divider()
        st.header("⚙️ Ações");
        if st.button("💾 Backup DB", key="backup_db_button"):
            try:
                if os.path.exists(DB_FILE): backup_dir = "backups_diario"; os.makedirs(backup_dir, exist_ok=True); ts = datetime.now().strftime("%Y%m%d_%H%M%S"); bf = os.path.join(backup_dir, f"{os.path.basename(DB_FILE)}_backup_{ts}.db"); shutil.copy2(DB_FILE, bf); st.success(f"Backup: {bf}")
                else: st.warning("DB não encontrado.")
            except Exception as e: st.error(f"Erro backup: {e}")
        st.subheader("Exportar Entradas")
        col_export1, col_export2 = st.columns(2)
        all_entries_export = get_all_entries_for_export()
        if not all_entries_export: st.caption("Nada a exportar.")
        else:
            df_export = pd.DataFrame(all_entries_export); df_export = df_export[['id', 'created_at', 'updated_at', 'content', 'tags', 'mood']]
            with col_export1:
                try: csv_data = df_export.to_csv(index=False, encoding='utf-8'); st.download_button("📄 CSV", csv_data, f"diario_{st.session_state.username}_exp_{datetime.now().strftime('%Y%m%d')}.csv", 'text/csv', key='csv_key')
                except Exception as e: st.error(f"Erro CSV: {e}")
            with col_export2:
                try: json_data = df_export.to_json(orient='records', indent=4, force_ascii=False); st.download_button("📑 JSON", json_data, f"diario_{st.session_state.username}_exp_{datetime.now().strftime('%Y%m%d')}.json", 'application/json', key='json_key')
                except Exception as e: st.error(f"Erro JSON: {e}")
        st.divider(); st.caption(f"Diário v10.0 | DB: {DB_FILE}")


    # --- Área Principal ---
    st.header("🗓️ Entradas do Diário")
    if st.session_state.filter_by_date: st.subheader(f"Mostrando de: {st.session_state.filter_by_date.strftime(DATE_ONLY_FORMAT)}")
    current_tag_filter_val = "" if st.session_state.tag_filter == "-- Todas --" else st.session_state.tag_filter
    total_items = count_entries(st.session_state.search_query, current_tag_filter_val, st.session_state.filter_by_date)
    total_pages = math.ceil(total_items / ITEMS_PER_PAGE) if total_items > 0 else 1
    if st.session_state.current_page > total_pages: st.session_state.current_page = max(1, total_pages)
    paginated_entries = get_entries(st.session_state.search_query, current_tag_filter_val, st.session_state.filter_by_date, st.session_state.current_page, ITEMS_PER_PAGE)

    if not paginated_entries: st.info("Nenhuma entrada encontrada.")
    else:
        for entry in paginated_entries:
            entry_id = entry['id']; is_editing = (st.session_state.editing_id == entry_id); is_confirming_delete = (st.session_state.confirming_delete_id == entry_id)
            try: created_time_str = datetime.fromisoformat(entry['created_at']).strftime(DATE_FORMAT); updated_time_str = datetime.fromisoformat(entry['updated_at']).strftime(DATE_FORMAT)
            except: created_time_str = "Inválida"; updated_time_str = "Inválida"
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
                            if update_entry(entry_id, edited_content, edited_tags, edited_mood): st.session_state.editing_id = None; st.session_state.entry_to_edit_content = ""; st.session_state.entry_to_edit_tags = ""; st.session_state.entry_to_edit_mood = MOOD_OPTIONS[0]; st.rerun()
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
                                if delete_entry(entry_id): st.session_state.confirming_delete_id = None; new_total_items = count_entries(st.session_state.search_query, current_tag_filter_val, st.session_state.filter_by_date); new_total_pages = math.ceil(new_total_items/ITEMS_PER_PAGE) if new_total_items > 0 else 1;
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