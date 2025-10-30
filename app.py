import psycopg2
import psycopg2.extras
# from flask_mysqldb import MySQL # REMOVIDO - Não é mais necessário
import hashlib
import os
import secrets
from flask import Flask, request, jsonify # Importações Flask ausentes adicionadas
from flask_cors import CORS
from datetime import date, datetime

app = Flask(__name__)
CORS(app)

# REMOVIDO - Não é mais necessário
# mysql = MySQL(app) 

def get_db_connection():
    """Retorna uma conexão ao banco de dados PostgreSQL."""
    conn = psycopg2.connect(os.environ.get('DATABASE_URL'))
    return conn


# --- ARMAZENAMENTO SIMPLES DE TOKEN PARA IMPERSONAÇÃO ---
# Em produção, use um cache (Redis) ou tabela de banco de dados
impersonation_tokens = {}


# --- Funções de Criptografia ---
def create_salt():
    return os.urandom(16).hex()

def hash_password(password, salt):
    salted_password = password.encode('utf-8') + salt.encode('utf-8')
    return hashlib.sha256(salted_password).hexdigest()

# --- Funções Auxiliares ---
def log_activity(user_id, action_text):
    """Registra uma ação no banco de dados activity_log."""
    if not user_id:
        return
    sql = "INSERT INTO activity_log (user_id, action_text) VALUES (%s, %s)"
    try:
        # 'with' gerencia commit, rollback e fechamento
        with get_db_connection() as conn:
            with conn.cursor() as cursor: # Não precisa de RealDictCursor aqui
                cursor.execute(sql, (user_id, action_text))
    except Exception as e:
        print(f"Erro ao registrar atividade: {e}")

# --- NOVO HELPER: Verificar se é Admin ---
def is_admin(user_id):
    """Verifica se o user_id pertence a um admin."""
    if not user_id:
        return False
    try:
        # 'with' abre e fecha a conexão e o cursor automaticamente
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("SELECT role FROM users WHERE id = %s", (user_id,))
                user = cursor.fetchone()
        
        # A conexão já está fechada aqui
        if user and user['role'] == 'admin':
            return True
        return False
    except Exception as e:
        print(f"Erro ao verificar admin: {e}")
        return False


# --- Rotas de Autenticação ---
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username, password, role, email = data.get('username'), data.get('password'), data.get('role'), data.get('email')
    job_title = data.get('job_title') or 'Funcionário' 
    admin_key_received = data.get('adminKey')
    consent = data.get('consent') 
    
    ADMIN_REGISTRATION_KEY = 'admin-secret-key' 
    
    if role == 'admin' and admin_key_received != ADMIN_REGISTRATION_KEY:
        return jsonify({'error': 'Chave de administrador incorreta.'}), 403
    
    if not consent:
        return jsonify({'error': 'Você deve aceitar os termos de privacidade para se registrar.'}), 400
        
    if not all([username, password, role]):
        return jsonify({'error': 'Dados obrigatórios ausentes.'}), 400
    
    try:
        new_user_id = None
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                
                cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
                if cursor.fetchone():
                    return jsonify({'error': 'Este nome de usuário já existe.'}), 409
                
                if email:
                    cursor.execute("SELECT email FROM users WHERE email = %s", (email,))
                    if cursor.fetchone():
                        return jsonify({'error': 'Este e-mail já está em uso.'}), 409
                        
                salt = create_salt()
                password_hash = hash_password(password, salt)
                needs_password_reset = (role == 'funcionario')
                
                # PostgreSQL usa RETURNING id para obter o novo ID
                cursor.execute(
                    """INSERT INTO users (username, password_hash, salt, role, email, needs_password_reset, job_title) 
                       VALUES (%s, %s, %s, %s, %s, %s, %s)
                       RETURNING id""",
                    (username, password_hash, salt, role, email, needs_password_reset, job_title)
                )
                
                # Obter o new_user_id retornado
                new_user_id = cursor.fetchone()['id']
                
            # O 'with conn' faz o commit automático aqui
            
        # Loga a atividade APÓS a transação ser bem-sucedida
        if new_user_id:
            log_activity(new_user_id, f"se registrou no sistema como {role}.")
        
        return jsonify({'message': 'Usuário registrado com sucesso.'}), 201
        
    except (Exception, psycopg2.Error) as e:
        print(f"Erro no registro: {e}")
        # O 'with conn' faz o rollback automático em caso de erro
        return jsonify({'error': f'Erro de banco de dados: {str(e)}'}), 500


@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username, password = data.get('username'), data.get('password')
    
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("SELECT id, username, password_hash, salt, role, email, needs_password_reset, job_title FROM users WHERE username = %s", (username,))
                user_row = cursor.fetchone()

        if not user_row:
            return jsonify({'error': 'Usuário não encontrado.'}), 404

        if hash_password(password, user_row['salt']) != user_row['password_hash']:
            return jsonify({'error': 'Senha incorreta.'}), 401

        user_data = {
            'id': user_row['id'],
            'username': user_row['username'],
            'email': user_row['email'],
            'role': user_row['role'],
            'jobTitle': user_row['job_title'],
            'needsPasswordReset': bool(user_row['needs_password_reset'])
        }
        
        log_activity(user_data['id'], f"fez login.")

        return jsonify({'message': 'Login bem-sucedido.', 'user': user_data}), 200
        
    except (Exception, psycopg2.Error) as e:
        print(f"Erro de login: {e}")
        return jsonify({'error': f'Erro de banco de dados: {str(e)}'}), 500


@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    email = request.json.get('email')
    if not email:
        return jsonify({'error': 'O e-mail é obrigatório.'}), 400

    try:
        user_id_for_log = None
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("SELECT id, salt FROM users WHERE email = %s", (email,))
                user = cursor.fetchone()

                if user:
                    user_id_for_log = user['id']
                    temp_password = secrets.token_hex(8)
                    password_hash = hash_password(temp_password, user['salt'])
                    cursor.execute(
                        "UPDATE users SET password_hash = %s, needs_password_reset = TRUE WHERE id = %s",
                        (password_hash, user['id'])
                    )
                    # 'with conn' faz o commit
                
        if user_id_for_log:
            log_activity(user_id_for_log, "solicitou uma redefinição de senha.")
        
    except (Exception, psycopg2.Error) as e:
        print(f"Erro no forgot-password: {e}")
        return jsonify({'error': f'Erro de banco de dados: {str(e)}'}), 500

    return jsonify({
        'message': 'Se existir uma conta com este e-mail, as instruções de redefinição foram processadas.'
    })


@app.route('/api/user/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    user_id, new_password = data.get('userId'), data.get('newPassword')

    if not all([user_id, new_password]):
        return jsonify({'error': 'Dados incompletos.'}), 400
        
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("SELECT salt FROM users WHERE id = %s", (user_id,))
                user = cursor.fetchone()

                if not user:
                    return jsonify({'error': 'Usuário não encontrado.'}), 404

                password_hash = hash_password(new_password, user['salt'])
                cursor.execute(
                    "UPDATE users SET password_hash = %s, needs_password_reset = FALSE WHERE id = %s",
                    (password_hash, user_id)
                )
                # 'with conn' faz o commit
        
        log_activity(user_id, "redefiniu sua senha após login forçado.")
        
        return jsonify({'message': 'Senha atualizada com sucesso.'})

    except (Exception, psycopg2.Error) as e:
        print(f"Erro no reset-password: {e}")
        return jsonify({'error': f'Erro de banco de dados: {str(e)}'}), 500


@app.route('/api/user/change-password', methods=['POST'])
def change_password():
    data = request.json
    user_id, old_password, new_password = data.get('userId'), data.get('oldPassword'), data.get('newPassword')

    if not all([user_id, old_password, new_password]):
        return jsonify({'error': 'Dados incompletos.'}), 400
        
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("SELECT password_hash, salt FROM users WHERE id = %s", (user_id,))
                user = cursor.fetchone()

                if not user:
                    return jsonify({'error': 'Usuário não encontrado.'}), 404
                    
                if hash_password(old_password, user['salt']) != user['password_hash']:
                    return jsonify({'error': 'Senha antiga incorreta.'}), 401

                new_password_hash = hash_password(new_password, user['salt'])
                cursor.execute(
                    "UPDATE users SET password_hash = %s, needs_password_reset = FALSE WHERE id = %s",
                    (new_password_hash, user_id)
                )
                # 'with conn' faz o commit
                
        log_activity(user_id, "alterou sua senha através do perfil.")
        
        return jsonify({'message': 'Senha atualizada com sucesso.'})

    except (Exception, psycopg2.Error) as e:
        print(f"Erro no change-password: {e}")
        return jsonify({'error': f'Erro de banco de dados: {str(e)}'}), 500


# --- ================================== ---
# --- NOVA ROTA (LGPD - Auto-Exclusão) ---
# --- ================================== ---
@app.route('/api/user/delete-self', methods=['POST'])
def delete_self_account():
    data = request.json
    user_id = data.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'ID de usuário não fornecido.'}), 400
        
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                
                cursor.execute("SELECT role FROM users WHERE id = %s", (user_id,))
                user = cursor.fetchone()
                if user and user['role'] == 'admin':
                    cursor.execute("SELECT COUNT(*) as admin_count FROM users WHERE role = 'admin'")
                    admin_count = cursor.fetchone()['admin_count']
                    if admin_count <= 1:
                        return jsonify({'error': 'Você não pode excluir sua conta pois é o único administrador. Por favor, promova outro usuário a administrador primeiro.'}), 403

                anon_username = f"usuario_anonimizado_{user_id}"
                anon_email = f"deleted_{user_id}@taskflow.up"
                null_salt = create_salt()
                null_pass = hash_password(secrets.token_hex(32), null_salt)
                
                cursor.execute(
                    """UPDATE users 
                       SET username = %s, 
                           email = %s, 
                           job_title = 'Ex-Funcionário', 
                           password_hash = %s, 
                           salt = %s,
                           needs_password_reset = TRUE
                       WHERE id = %s""",
                    (anon_username, anon_email, null_pass, null_salt, user_id)
                )
                
                cursor.execute("UPDATE task_comments SET text = '[comentário removido pelo usuário]' WHERE user_id = %s", (user_id,))
                cursor.execute("UPDATE chat_messages SET text = '[mensagem removida pelo usuário]' WHERE user_id = %s", (user_id,))
                # 'with conn' faz o commit
        
        log_text = f"teve sua conta anonimizada (auto-exclusão, ID: {user_id})."
        log_activity(user_id, log_text) 
        
        return jsonify({'message': 'Conta anonimizada com sucesso.'}), 200
        
    except (Exception, psycopg2.Error) as e:
        print(f"Erro ao anonimizar conta: {e}")
        return jsonify({'error': f'Erro ao processar exclusão de conta: {str(e)}'}), 500


# --- Rotas de Usuário ---

@app.route('/api/user/<int:user_id>', methods=['GET'])
def get_user_details(user_id):
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("SELECT id, username, email, role, job_title FROM users WHERE id = %s", (user_id,))
                user = cursor.fetchone()
        if not user:
            return jsonify({'error': 'Usuário não encontrado.'}), 404
        return jsonify(user)
    except (Exception, psycopg2.Error) as e:
        print(f"Erro em get_user_details: {e}")
        return jsonify({'error': f'Erro de banco de dados: {str(e)}'}), 500

@app.route('/api/user/<int:user_id>', methods=['PUT'])
def update_user_profile(user_id):
    data = request.json
    acting_user_id = data.get('acting_user_id')
    
    if not acting_user_id:
        return jsonify({'error': 'ID do usuário atuante é obrigatório.'}), 401
        
    if acting_user_id != user_id and not is_admin(acting_user_id):
        return jsonify({'error': 'Permissão negada.'}), 403

    new_username, new_email, new_job_title = data.get('username'), data.get('email'), data.get('job_title') 
    
    if not new_username or not new_email:
        return jsonify({'error': 'Nome de usuário e e-mail são obrigatórios.'}), 400

    try:
        updated_user = None
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("SELECT id FROM users WHERE username = %s AND id != %s", (new_username, user_id))
                if cursor.fetchone():
                    return jsonify({'error': 'Este nome de usuário já está em uso.'}), 409
                
                cursor.execute("SELECT id FROM users WHERE email = %s AND id != %s", (new_email, user_id))
                if cursor.fetchone():
                    return jsonify({'error': 'Este e-mail já está em uso.'}), 409

                if is_admin(acting_user_id) and 'role' in data:
                    new_role = data.get('role')
                    if new_role not in ['admin', 'funcionario']:
                        return jsonify({'error': 'Role inválido.'}), 400
                    cursor.execute(
                        "UPDATE users SET username = %s, email = %s, job_title = %s, role = %s WHERE id = %s", 
                        (new_username, new_email, new_job_title, new_role, user_id)
                    )
                else:
                    cursor.execute(
                        "UPDATE users SET username = %s, email = %s, job_title = %s WHERE id = %s", 
                        (new_username, new_email, new_job_title, user_id)
                    )
                
                cursor.execute("SELECT id, username, email, role, job_title FROM users WHERE id = %s", (user_id,))
                updated_user = cursor.fetchone()
                # 'with conn' faz o commit
        
        if updated_user:
            if acting_user_id == user_id:
                log_activity(acting_user_id, f"atualizou seu próprio perfil.")
            else:
                log_activity(acting_user_id, f"atualizou o perfil do usuário {updated_user['username']} (ID: {user_id}).")
        
        return jsonify({'message': 'Perfil atualizado com sucesso.', 'user': updated_user})

    except (Exception, psycopg2.Error) as e:
        print(f"Erro em update_user_profile: {e}")
        return jsonify({'error': f'Erro de banco de dados: {str(e)}'}), 500


@app.route('/api/users/employees', methods=['GET'])
def get_employees():
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("SELECT id, username, email, job_title FROM users WHERE role = 'funcionario' ORDER BY username ASC")
                employees = cursor.fetchall()
        return jsonify(employees)
    except (Exception, psycopg2.Error) as e:
        print(f"Erro em get_employees: {e}")
        return jsonify({'error': f'Erro de banco de dados: {str(e)}'}), 500


# --- ROTA DE ANÁLISE ---
@app.route('/api/analytics', methods=['GET'])
def get_analytics():
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("SELECT COUNT(*) as total FROM tasks")
                total_tasks = cursor.fetchone()['total']
                cursor.execute("SELECT COUNT(*) as total FROM tasks WHERE completed = TRUE")
                completed_tasks = cursor.fetchone()['total']
                cursor.execute("SELECT COUNT(*) as total FROM tasks WHERE completed = FALSE")
                pending_tasks = cursor.fetchone()['total']
                
                # CORREÇÃO: CURDATE() (MySQL) -> CURRENT_DATE (PostgreSQL)
                cursor.execute("SELECT COUNT(*) as total FROM tasks WHERE completed = FALSE AND due_date < CURRENT_DATE")
                overdue_tasks = cursor.fetchone()['total']
                
                query = """
                    SELECT u.username, COUNT(t.id) as task_count
                    FROM tasks t
                    JOIN users u ON t.assigned_to_id = u.id
                    WHERE u.role = 'funcionario'
                    GROUP BY u.username
                    ORDER BY task_count DESC
                    LIMIT 1
                """
                cursor.execute(query)
                top_user = cursor.fetchone()
        
        analytics_data = {
            "totalTasks": total_tasks,
            "completedTasks": completed_tasks,
            "pendingTasks": pending_tasks,
            "overdueTasks": overdue_tasks,
            "topUser": top_user if top_user else {"username": "N/A", "task_count": 0}
        }
        return jsonify(analytics_data)
        
    except (Exception, psycopg2.Error) as e:
        print(f"Erro em get_analytics: {e}")
        return jsonify({'error': f'Erro de banco de dados: {str(e)}'}), 500


# --- Rotas de Tarefas ---
@app.route('/api/tasks', methods=['GET', 'POST'])
def tasks():
    try:
        if request.method == 'GET':
            query = """
                SELECT t.*, u_creator.username AS creator_name, u_assignee.username AS assignee_name, COUNT(tc.id) AS comment_count
                FROM tasks t
                LEFT JOIN users u_creator ON t.creator_id = u_creator.id
                LEFT JOIN users u_assignee ON t.assigned_to_id = u_assignee.id
                LEFT JOIN task_comments tc ON t.id = tc.task_id
                GROUP BY t.id, u_creator.username, u_assignee.username 
                ORDER BY t.completed ASC, t.priority ASC, t.due_date ASC
            """
            with get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    cursor.execute(query)
                    tasks_list = cursor.fetchall()
            
            for task in tasks_list:
                for key, value in task.items():
                    if isinstance(value, (datetime, date)): task[key] = value.isoformat()
            return jsonify(tasks_list)
        
        if request.method == 'POST':
            data = request.json
            creator_id, assigned_to_id = data.get('creator_id'), data.get('assigned_to_id') or None
            due_date = data.get('due_date') or None
            created_at_time = datetime.now()
            
            sql = "INSERT INTO tasks (title, description, priority, due_date, creator_id, assigned_to_id, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)"
            
            with get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(sql, (data.get('title'), data.get('description'), data.get('priority'), due_date, creator_id, assigned_to_id, created_at_time))
            
            log_activity(creator_id, f"criou a tarefa: '{data.get('title')}'")
            return jsonify({'message': 'Tarefa criada com sucesso.'}), 201
            
    except (Exception, psycopg2.Error) as e:
        print(f"Erro em tasks (GET/POST): {e}")
        return jsonify({'error': f'Erro de banco de dados: {str(e)}'}), 500


@app.route('/api/tasks/<int:task_id>', methods=['GET', 'PUT', 'DELETE'])
def manage_task(task_id):
    try:
        if request.method == 'GET':
            with get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    cursor.execute("SELECT * FROM tasks WHERE id = %s", (task_id,))
                    task = cursor.fetchone()
            if task:
                for key, value in task.items():
                    if isinstance(value, (datetime, date)): task[key] = value.isoformat()
                return jsonify(task)
            return jsonify({'error': 'Tarefa não encontrada.'}), 404

        if request.method == 'PUT':
            data = request.json
            acting_user_id = data.get('acting_user_id')
            
            with get_db_connection() as conn:
                with conn.cursor() as cursor:
                    if 'completed' in data:
                        cursor.execute("UPDATE tasks SET completed = %s WHERE id = %s", (data['completed'], task_id))
                        action_text = "concluiu" if data['completed'] else "reabriu"
                        log_activity(acting_user_id, f"{action_text} a tarefa ID {task_id}.")
                    else:
                        assigned_to_id = data.get('assigned_to_id') or None
                        due_date = data.get('due_date') or None
                        cursor.execute(
                            "UPDATE tasks SET title = %s, description = %s, priority = %s, due_date = %s, assigned_to_id = %s WHERE id = %s",
                            (data.get('title'), data.get('description'), data.get('priority'), due_date, assigned_to_id, task_id)
                        )
                        log_activity(acting_user_id, f"editou a tarefa ID {task_id} (novo título: '{data.get('title')}')")
            
            return jsonify({'message': f'Tarefa {task_id} atualizada.'})

        if request.method == 'DELETE':
            data = request.json if request.is_json else {}
            acting_user_id = data.get('acting_user_id')
            
            with get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("DELETE FROM tasks WHERE id = %s", (task_id,))
            
            log_activity(acting_user_id, f"excluiu a tarefa ID {task_id}.")
            return jsonify({'message': f'Tarefa {task_id} deletada.'})
            
    except (Exception, psycopg2.Error) as e:
        print(f"Erro em manage_task: {e}")
        return jsonify({'error': f'Erro de banco de dados: {str(e)}'}), 500


# --- Rotas de Comentários ---
@app.route('/api/tasks/<int:task_id>/comments', methods=['GET', 'POST'])
def comments(task_id):
    try:
        if request.method == 'GET':
            with get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    cursor.execute("SELECT tc.*, u.username FROM task_comments tc JOIN users u ON tc.user_id = u.id WHERE tc.task_id = %s ORDER BY tc.timestamp ASC", (task_id,))
                    comments_list = cursor.fetchall()
            
            for comment in comments_list:
                if isinstance(comment.get('timestamp'), datetime): comment['timestamp'] = comment['timestamp'].isoformat()
            return jsonify(comments_list)
        
        if request.method == 'POST':
            data = request.json
            user_id = data.get('user_id')
            text = data.get('text')
            
            with get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("INSERT INTO task_comments (task_id, user_id, text) VALUES (%s, %s, %s)", (task_id, user_id, text))
            
            log_activity(user_id, f"comentou na tarefa ID {task_id}: '{text[:30]}...'")
            return jsonify({'message': 'Comentário adicionado.'}), 201
            
    except (Exception, psycopg2.Error) as e:
        print(f"Erro em comments: {e}")
        return jsonify({'error': f'Erro de banco de dados: {str(e)}'}), 500


# --- Rotas de Chat ---
@app.route('/api/chat/messages', methods=['GET', 'POST'])
def chat_messages():
    try:
        if request.method == 'GET':
            with get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    cursor.execute("SELECT cm.*, u.username, u.role FROM chat_messages cm JOIN users u ON cm.user_id = u.id ORDER BY cm.timestamp ASC")
                    messages = cursor.fetchall()
            
            for msg in messages:
                if isinstance(msg.get('timestamp'), datetime): msg['timestamp'] = msg['timestamp'].isoformat()
            return jsonify(messages)
        
        if request.method == 'POST':
            data = request.json
            with get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("INSERT INTO chat_messages (user_id, text) VALUES (%s, %s)", (data.get('user_id'), data.get('text')))
            
            return jsonify({'message': 'Mensagem enviada.'}), 201

    except (Exception, psycopg2.Error) as e:
        print(f"Erro em chat_messages: {e}")
        return jsonify({'error': f'Erro de banco de dados: {str(e)}'}), 500


# --- ROTA DE LOG DE ATIVIDADES ---
@app.route('/api/activity-log', methods=['GET'])
def get_activity_log():
    try:
        query = """
            SELECT a.id, a.action_text, a.timestamp, u.username
            FROM activity_log a
            LEFT JOIN users u ON a.user_id = u.id
            ORDER BY a.timestamp DESC
            LIMIT 50
        """
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(query)
                logs = cursor.fetchall()
        
        for log_entry in logs:
            if isinstance(log_entry.get('timestamp'), datetime):
                log_entry['timestamp'] = log_entry['timestamp'].isoformat()
            if not log_entry['username']:
                # Isso acontecerá se o user_id foi setado para NULL por ON DELETE SET NULL
                log_entry['username'] = "[Usuário Deletado]"
                
        return jsonify(logs)

    except (Exception, psycopg2.Error) as e:
        print(f"Erro em get_activity_log: {e}")
        return jsonify({'error': f'Erro de banco de dados: {str(e)}'}), 500


# --- ============================================ ---
# --- NOVAS ROTAS SSAP (Admin User Management) ---
# --- ============================================ ---

@app.route('/api/admin/users', methods=['GET'])
def admin_get_all_users():
    admin_id = request.args.get('admin_user_id')
    if not is_admin(admin_id):
        return jsonify({'error': 'Acesso negado. Requer privilégios de administrador.'}), 403
        
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("SELECT id, username, email, role, job_title, needs_password_reset FROM users ORDER BY username ASC")
                users = cursor.fetchall()
        return jsonify(users)
    except (Exception, psycopg2.Error) as e:
        print(f"Erro em admin_get_all_users: {e}")
        return jsonify({'error': f'Erro de banco de dados: {str(e)}'}), 500

@app.route('/api/admin/user/<int:user_id>', methods=['DELETE'])
def admin_delete_user(user_id):
    data = request.json
    admin_id = data.get('admin_user_id')
    
    if not is_admin(admin_id):
        return jsonify({'error': 'Acesso negado.'}), 403
    if admin_id == user_id:
        return jsonify({'error': 'Você não pode deletar a si mesmo.'}), 400

    try:
        username_to_log = None
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                
                cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
                user = cursor.fetchone()
                if not user:
                    return jsonify({'error': 'Usuário não encontrado.'}), 404
                username_to_log = user['username']

                # SIMPLIFICADO: O seu SQL usa "ON DELETE CASCADE" e "ON DELETE SET NULL".
                # O banco de dados limpará tasks, comments, chat e logs automaticamente.
                # Só precisamos deletar o usuário.
                
                cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
                # 'with conn' faz o commit
        
        if username_to_log:
            log_activity(admin_id, f"deletou o usuário {username_to_log} (ID: {user_id}).")
        
        return jsonify({'message': 'Usuário deletado com sucesso.'})
        
    except (Exception, psycopg2.Error) as e:
        print(f"Erro ao deletar usuário: {e}")
        return jsonify({'error': f'Erro de banco de dados: {str(e)}'}), 500


@app.route('/api/admin/force-reset-password', methods=['POST'])
def admin_force_reset_password():
    data = request.json
    admin_id = data.get('admin_user_id')
    target_user_id = data.get('target_user_id')
    
    if not is_admin(admin_id):
        return jsonify({'error': 'Acesso negado.'}), 403

    try:
        username_to_log = None
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("SELECT salt, username FROM users WHERE id = %s", (target_user_id,))
                user = cursor.fetchone()
                if not user:
                    return jsonify({'error': 'Usuário não encontrado.'}), 404
                
                username_to_log = user['username']
                temp_password = secrets.token_hex(8)
                password_hash = hash_password(temp_password, user['salt'])
                
                cursor.execute(
                    "UPDATE users SET password_hash = %s, needs_password_reset = TRUE WHERE id = %s",
                    (password_hash, target_user_id)
                )
                # 'with conn' faz o commit
        
        if username_to_log:
            log_activity(admin_id, f"forçou a redefinição de senha para o usuário {username_to_log} (ID: {target_user_id}).")
        
        return jsonify({
            'message': f"Redefinição de senha forçada para {username_to_log}. O usuário deverá criar uma nova senha no próximo login."
        })

    except (Exception, psycopg2.Error) as e:
        print(f"Erro em force_reset_password: {e}")
        return jsonify({'error': f'Erro de banco de dados: {str(e)}'}), 500

# --- ROTAS DE IMPERSONAÇÃO (SSO) ---

@app.route('/api/admin/impersonate', methods=['POST'])
def admin_impersonate_start():
    data = request.json
    admin_id = data.get('admin_user_id')
    target_user_id = data.get('target_user_id')

    if not is_admin(admin_id):
        return jsonify({'error': 'Acesso negado.'}), 403
    if admin_id == target_user_id:
        return jsonify({'error': 'Você não pode impersonar a si mesmo.'}), 400

    token = secrets.token_hex(32)
    impersonation_tokens[token] = {
        'admin_id': admin_id,
        'target_user_id': target_user_id,
        'expires_at': datetime.now().timestamp() + 60
    }
    
    log_activity(admin_id, f"iniciou uma sessão de impersonação para o usuário ID {target_user_id}.")
    
    return jsonify({'token': token})

@app.route('/api/impersonate/login', methods=['POST'])
def impersonate_login():
    token = request.json.get('token')
    
    if not token or token not in impersonation_tokens:
        return jsonify({'error': 'Token de impersonação inválido ou expirado.'}), 403
        
    token_data = impersonation_tokens.pop(token)
    
    if datetime.now().timestamp() > token_data['expires_at']:
        return jsonify({'error': 'Token de impersonação expirado.'}), 403

    target_user_id = token_data['target_user_id']
    admin_id = token_data['admin_id']
    
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("SELECT id, username, email, role, job_title FROM users WHERE id = %s", (target_user_id,))
                user_row = cursor.fetchone()
        
        if not user_row:
            return jsonify({'error': 'Usuário alvo não encontrado.'}), 404

        user_data = {
            'id': user_row['id'],
            'username': user_row['username'],
            'email': user_row['email'],
            'role': user_row['role'],
            'jobTitle': user_row['job_title'],
            'needsPasswordReset': False, 
            'impersonating': True,
            'original_admin_id': admin_id
        }
        
        return jsonify({'message': 'Impersonação bem-sucedida.', 'user': user_data}), 200

    except (Exception, psycopg2.Error) as e:
        print(f"Erro em impersonate_login: {e}")
        return jsonify({'error': f'Erro de banco de dados: {str(e)}'}), 500


if __name__ == '__main__':
    # Obtém a porta da variável de ambiente PORT, com padrão 5001 se não definida
    # Isso é útil para plataformas de deploy como o Render
    port = int(os.environ.get('PORT', 5001))
    app.run(debug=True, host='0.0.0.0', port=port)
