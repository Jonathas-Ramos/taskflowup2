document.addEventListener('DOMContentLoaded', () => {
    // --- VARIÁVEIS GLOBAIS ---
    const API_URL = '/api';;
    let currentUser = null;
    let allTasks = [];
    let currentFilter = 'all';
    let editTaskModal, commentsModal, confirmationModal, forceResetModal, adminUserEditModal;

    // --- SELETORES DO DOM ---
    const authContainer = document.querySelector('.auth-container');
    const appContainer = document.querySelector('.app-container');
    const mainContent = document.getElementById('main-content');
    
    // --- SELETORES DE IMPERSONAÇÃO (Variável 'stopImpersonationBtn' REMOVIDA daqui) ---
    const impersonationBanner = document.getElementById('impersonation-banner');
    const impersonationUsername = document.getElementById('impersonation-username');


    // --- AUTENTICAÇÃO / FORM SWITCH ---
    const showSection = (sectionToShow) => {
        [document.getElementById('login-section'), document.getElementById('registration-section'), document.getElementById('forgot-password-section')].forEach(s => s.style.display = 'none');
        sectionToShow.style.display = 'block';
    };
    document.getElementById('show-register').addEventListener('click', (e) => { e.preventDefault(); showSection(document.getElementById('registration-section')); });
    document.getElementById('show-login').addEventListener('click', (e) => { e.preventDefault(); showSection(document.getElementById('login-section')); });
    document.getElementById('show-forgot-password').addEventListener('click', (e) => { e.preventDefault(); showSection(document.getElementById('forgot-password-section')); });
    document.getElementById('show-login-from-forgot').addEventListener('click', (e) => { e.preventDefault(); showSection(document.getElementById('login-section')); });

    // Registration (com alteração)
    try {
        document.getElementById('register-form').elements.role.forEach(radio => {
            radio.addEventListener('change', (e) => {
                const isAdmin = e.target.value === 'admin';
                document.getElementById('admin-fields').style.display = isAdmin ? 'block' : 'none';
                document.getElementById('employee-fields').style.display = isAdmin ? 'none' : 'block';
                document.getElementById('admin-key').required = isAdmin;
                document.getElementById('register-email').required = !isAdmin;
            });
        });
    } catch(e) { /* form might differ per deployment; ignore safely */ }

    document.getElementById('register-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const err = document.getElementById('register-error');
        err.textContent = '';
        const fd = {
            username: e.target.elements['register-username'].value.trim(),
            password: e.target.elements['register-password'].value,
            role: e.target.elements.role.value,
            email: document.getElementById('register-email').value.trim(),
            job_title: document.getElementById('register-job-title').value.trim(),
            adminKey: document.getElementById('admin-key').value,
            // MELHORIA LGPD: Envia o status do consentimento
            consent: e.target.elements['register-consent'].checked
        };
        try {
            const res = await fetch(`${API_URL}/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(fd)
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Erro ao registrar');
            alert('Usuário registrado com sucesso!');
            showSection(document.getElementById('login-section'));
            e.target.reset();
        } catch (error) {
            err.textContent = error.message;
        }
    });

    // Login (sem alterações)
    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const err = document.getElementById('login-error');
        err.textContent = '';
        try {
            const res = await fetch(`${API_URL}/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: e.target.elements.username.value, password: e.target.elements.password.value })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Erro ao logar');
            if (data.user && data.user.needsPasswordReset) {
                currentUser = data.user;
                forceResetModal = new bootstrap.Modal(document.getElementById('forcePasswordResetModal'));
                forceResetModal.show();
            } else {
                startSession(data.user);
            }
        } catch (error) {
            err.textContent = error.message;
        }
    });

    // Forgot password (com alteração)
    document.getElementById('forgot-password-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const fb = document.getElementById('forgot-feedback');
        fb.textContent = '';
        fb.classList.remove('text-success');
        try {
            const res = await fetch(`${API_URL}/forgot-password`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: e.target.elements['forgot-email'].value })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Erro ao recuperar senha');
            
            // MELHORIA LGPD/SEGURANÇA: Nunca exiba a senha temporária no frontend.
            // Apenas mostre a mensagem de sucesso genérica do backend.
            fb.textContent = data.message;
            fb.classList.add('text-success');
            
        } catch (error) {
            fb.textContent = error.message;
        }
    });

    // Force reset form inside modal (sem alterações)
    try {
        document.getElementById('force-reset-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const err = document.getElementById('force-reset-error');
            const newPass = document.getElementById('reset-new-password').value;
            const confPass = document.getElementById('reset-confirm-password').value;
            err.textContent = '';
            if (newPass.length < 4) { err.textContent = 'A senha deve ter pelo menos 4 caracteres.'; return; }
            if (newPass !== confPass) { err.textContent = 'As senhas não coincidem.'; return; }
            try {
                const res = await fetch(`${API_URL}/user/reset-password`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ userId: currentUser.id, newPassword: newPass })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Erro ao resetar senha');
                alert('Senha atualizada com sucesso!');
                forceResetModal.hide();
                // O usuário não está mais "impersonando" se ele teve que resetar
                if (currentUser.impersonating) {
                    localStorage.removeItem('originalAdminSession');
                }
                currentUser.needsPasswordReset = false;
                startSession(currentUser);
            } catch (error) {
                err.textContent = error.message;
            }
        });
    } catch(e) { /* ok if modal not present */ }

    // --- SESSÃO ---
    function startSession(user) {
        currentUser = user;
        authContainer.style.display = 'none';
        appContainer.style.display = 'flex';
        document.getElementById('chat-container').style.display = 'block';
        document.getElementById('header-username').textContent = currentUser.username;
        
        const isAdmin = currentUser.role === 'admin';
        
        // --- ATUALIZAÇÃO PARA IMPERSONAÇÃO E LINKS DE ADMIN ---
        const navLogout = document.getElementById('nav-logout');
        
        if (currentUser.impersonating) {
            // Está impersonando
            impersonationBanner.style.display = 'flex';
            impersonationUsername.textContent = currentUser.username;
            // Altera o botão de logout para "Parar Impersonação"
            navLogout.innerHTML = `<a href="#"><i class="bi bi-box-arrow-in-right"></i><span>Retornar ao Admin</span></a>`;
            // Esconde links de admin mesmo se o usuário impersonado for admin
            document.getElementById('nav-activity-log').style.display = 'none';
            document.getElementById('nav-ssap').style.display = 'none';
        } else {
            // Sessão normal
            impersonationBanner.style.display = 'none';
            // Garante que o botão de logout esteja no estado normal
            navLogout.innerHTML = `<a href="#"><i class="bi bi-box-arrow-left"></i><span>Sair</span></a>`;
            // Mostra/esconde links de admin baseado no role real
            document.getElementById('nav-activity-log').style.display = isAdmin ? 'list-item' : 'none';
            document.getElementById('nav-ssap').style.display = isAdmin ? 'list-item' : 'none';
        }
        
        // Configura event listeners APÓS o HTML do botão de logout ser definido
        setupEventListeners();
        renderView('dashboard');
    }
    
    function logout() {
        // --- ATUALIZAÇÃO PARA IMPERSONAÇÃO ---
        if (currentUser && currentUser.impersonating) {
            // --- ESTÁ SAINDO DA IMPERSONAÇÃO ---
            const adminSessionStr = localStorage.getItem('originalAdminSession');
            localStorage.removeItem('originalAdminSession');
            if (adminSessionStr) {
                const adminSession = JSON.parse(adminSessionStr);
                // Restaura a sessão do admin
                startSession(adminSession);
            } else {
                // Failsafe: se não encontrar a sessão do admin, faz logout completo
                performFullLogout();
            }
        } else {
            // --- LOGOUT NORMAL ---
            performFullLogout();
        }
    }
    
    function performFullLogout() {
        // Esta é a lógica de logout original
        currentUser = null; 
        allTasks = [];
        localStorage.removeItem('originalAdminSession'); // Limpa por segurança
        appContainer.style.display = 'none';
        mainContent.innerHTML = '';
        document.getElementById('chat-container').style.display = 'none';
        authContainer.style.display = 'flex';
        showSection(document.getElementById('login-section'));
        document.getElementById('login-form').reset();
    }

    // --- ================================== ---
    // --- EVENT LISTENERS GERAIS (CORRIGIDO) ---
    // --- ================================== ---
    function setupEventListeners() {
        // Remove listeners antigos para evitar duplicação
        
        const oldToggle = document.getElementById('sidebar-toggle');
        if (oldToggle && oldToggle.parentNode) {
            const newToggle = oldToggle.cloneNode(true);
            oldToggle.parentNode.replaceChild(newToggle, oldToggle);
            newToggle.addEventListener('click', () => {
                document.body.classList.toggle('sidebar-collapsed');
            });
        }

        const oldLogout = document.getElementById('nav-logout');
        if (oldLogout && oldLogout.parentNode) {
            const newLogout = oldLogout.cloneNode(true);
            oldLogout.parentNode.replaceChild(newLogout, oldLogout);
            newLogout.addEventListener('click', logout);
        }
        
        // O botão de parar impersonação no banner também chama a função logout
        // AQUI ESTÁ A CORREÇÃO: Busca o elemento do DOM toda vez, em vez de usar uma variável global obsoleta.
        const oldStopImpersonation = document.getElementById('stop-impersonation-btn');
        if (oldStopImpersonation && oldStopImpersonation.parentNode) {
            const newStopImpersonation = oldStopImpersonation.cloneNode(true);
            oldStopImpersonation.parentNode.replaceChild(newStopImpersonation, oldStopImpersonation);
            newStopImpersonation.addEventListener('click', logout);
        }

        const oldUserInfo = document.getElementById('header-user-info');
        if (oldUserInfo && oldUserInfo.parentNode) {
            const newUserInfo = oldUserInfo.cloneNode(true);
            oldUserInfo.parentNode.replaceChild(newUserInfo, oldUserInfo);
            newUserInfo.addEventListener('click', () => {
                renderView('profile');
            });
        }

        document.querySelectorAll('#sidebar .components li').forEach(item => {
            if (item && item.parentNode) { // Adiciona verificação de segurança
                const newItem = item.cloneNode(true);
                item.parentNode.replaceChild(newItem, item);
                newItem.addEventListener('click', (e) => {
                    e.preventDefault();
                    const view = newItem.getAttribute('data-view');
                    if (view) renderView(view);
                });
            }
        });
    }

    // --- RENDERIZAÇÃO DE VIEWS ---
    function renderView(viewName) {
        document.querySelector('#sidebar .components li.active')?.classList.remove('active');
        document.querySelector(`#sidebar .components li[data-view="${viewName}"]`)?.classList.add('active');
        document.getElementById('header-search-container').style.display = 'none';

        if (viewName === 'dashboard') renderDashboardView();
        else if (viewName === 'analytics') renderAnalyticsView();
        else if (viewName === 'profile') renderProfileView();
        else if (viewName === 'team') renderTeamView();
        else if (viewName === 'log') renderActivityLogView();
        else if (viewName === 'ssap') renderSSAPView(); // NOVA VIEW
    }

    // --- PROFILE VIEW ---
    async function renderProfileView() {
        mainContent.innerHTML = `
            <div class="content-header"><h2>Meu Perfil</h2></div>
            <div class="row">
                <div class="col-lg-6">
                    <div class="card"><div class="card-header"><h5 class="mb-0">Detalhes do Perfil</h5></div>
                    <div class="card-body">
                        <form id="profile-form">
                            <div class="mb-3">
                                <label for="profile-username" class="form-label">Nome de Usuário</label>
                                <input type="text" class="form-control" id="profile-username" required>
                            </div>
                            <div class="mb-3">
                                <label for="profile-email" class="form-label">E-mail</label>
                                <input type="email" class="form-control" id="profile-email" required>
                            </div>
                            <div class="mb-3">
                                <label for="profile-job-title" class="form-label">Cargo</label>
                                <input type="text" class="form-control" id="profile-job-title" placeholder="Ex: Desenvolvedor Jr.">
                            </div>
                            <div id="profile-error" class="error-message"></div>
                            <div id="profile-success" class="text-success mb-2"></div>
                            <button type="submit" class="btn btn-primary" ${currentUser.impersonating ? 'disabled' : ''}>Salvar Alterações</button>
                            ${currentUser.impersonating ? '<p class="text-danger small mt-2">Você não pode editar um perfil enquanto estiver impersonando.</p>' : ''}
                        </form>
                    </div></div>
                </div>
                <div class="col-lg-6">
                    <div class="card"><div class="card-header"><h5 class="mb-0">Alterar Senha</h5></div>
                    <div class="card-body">
                        <form id="change-password-form">
                            <div class="mb-3">
                                <label for="old-password" class="form-label">Senha Antiga</label>
                                <input type="password" class="form-control" id="old-password" required>
                            </div>
                            <div class="mb-3">
                                <label for="new-password" class="form-label">Nova Senha</label>
                                <input type="password" class="form-control" id="new-password" required>
                            </div>
                            <div class="mb-3">
                                <label for="confirm-password" class="form-label">Confirmar Nova Senha</label>
                                <input type="password" class="form-control" id="confirm-password" required>
                            </div>
                            <div id="password-error" class="error-message"></div>
                            <div id="password-success" class="text-success mb-2"></div>
                            <button type="submit" class="btn btn-primary" ${currentUser.impersonating ? 'disabled' : ''}>Alterar Senha</button>
                            ${currentUser.impersonating ? '<p class="text-danger small mt-2">Você não pode alterar a senha enquanto estiver impersonando.</p>' : ''}
                        </form>
                    </div></div>
                </div>
                
                <div class="col-12 mt-4">
                    <div class="card border-danger">
                        <div class="card-header bg-danger text-white"><h5 class="mb-0">Zona de Perigo</h5></div>
                        <div class="card-body">
                            <p class="text-muted">Esta ação não pode ser desfeita. Sua conta será permanentemente anonimizada, removendo todos os seus dados pessoais (e-mail, nome de usuário) e limpando seus comentários e mensagens do chat. Suas tarefas criadas permanecerão, mas serão atribuídas a um "usuário anônimo".</p>
                            <button id="delete-account-btn" class="btn btn-danger" ${currentUser.impersonating ? 'disabled' : ''}>
                                Excluir Minha Conta Permanentemente
                            </button>
                            ${currentUser.impersonating ? '<p class="text-danger small mt-2">Ações de exclusão estão desabilitadas durante a impersonação.</p>' : ''}
                        </div>
                    </div>
                </div>
            </div>`;
        try {
            // Pega dados do usuário ATUAL (seja ele normal ou impersonado)
            const response = await fetch(`${API_URL}/user/${currentUser.id}`);
            if (!response.ok) throw new Error('Não foi possível carregar os dados do perfil.');
            const userData = await response.json();
            document.getElementById('profile-username').value = userData.username;
            document.getElementById('profile-email').value = userData.email;
            document.getElementById('profile-job-title').value = userData.job_title || '';
        } catch(error) {
            document.getElementById('profile-error').textContent = error.message;
        }

        document.getElementById('profile-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            if (currentUser.impersonating) return; // Segurança
            
            const errorEl = document.getElementById('profile-error');
            const successEl = document.getElementById('profile-success');
            errorEl.textContent = '';
            successEl.textContent = '';
            const updatedData = {
                username: document.getElementById('profile-username').value.trim(),
                email: document.getElementById('profile-email').value.trim(),
                job_title: document.getElementById('profile-job-title').value.trim(),
                // ATUALIZADO: Envia quem está fazendo a ação
                acting_user_id: currentUser.id 
            };
            try {
                const response = await fetch(`${API_URL}/user/${currentUser.id}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(updatedData)
                });
                const data = await response.json();
                if (!response.ok) throw new Error(data.error || 'Erro ao atualizar perfil');
                // Atualiza o objeto currentUser local
                currentUser.username = data.user.username;
                currentUser.email = data.user.email;
                currentUser.jobTitle = data.user.job_title;
                document.getElementById('header-username').textContent = currentUser.username;
                successEl.textContent = 'Perfil atualizado com sucesso!';
            } catch (error) {
                errorEl.textContent = error.message;
            }
        });

        document.getElementById('change-password-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            if (currentUser.impersonating) return; // Segurança

            const errorEl = document.getElementById('password-error');
            const successEl = document.getElementById('password-success');
            errorEl.textContent = '';
            successEl.textContent = '';
            const oldPassword = document.getElementById('old-password').value;
            const newPassword = document.getElementById('new-password').value;
            const confirmPassword = document.getElementById('confirm-password').value;
            if (newPassword !== confirmPassword) {
                errorEl.textContent = 'As novas senhas não coincidem.';
                return;
            }
            try {
                const response = await fetch(`${API_URL}/user/change-password`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ userId: currentUser.id, oldPassword, newPassword })
                });
                // ATUALIZADO: 'res' não estava definido, trocado por 'response'
                const data = await response.json(); 
                if (!response.ok) throw new Error(data.error || 'Erro ao alterar senha');
                successEl.textContent = data.message;
                e.target.reset();
            } catch (error) {
                errorEl.textContent = error.message;
            }
        });
        
        // MELHORIA LGPD: Adiciona listener para o novo botão de exclusão
        document.getElementById('delete-account-btn').addEventListener('click', handleDeleteSelfAccount);
    }
    
    // --- ================================== ---
    // --- NOVA FUNÇÃO (LGPD - Auto-Exclusão) ---
    // --- ================================== ---
    function handleDeleteSelfAccount(e) {
        if (currentUser.impersonating) return; // Segurança

        const confirmationText = 'Tem certeza que deseja EXCLUIR sua conta? Esta ação é permanente e irá anonimizar todos os seus dados pessoais (nome, e-mail) e limpar seus comentários e mensagens de chat.';
        
        document.getElementById('confirmation-modal-body').textContent = confirmationText;
        const confirmBtn = document.getElementById('confirm-action-btn');
        
        const newConfirmBtn = confirmBtn.cloneNode(true);
        confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);

        newConfirmBtn.addEventListener('click', async () => {
            try {
                const res = await fetch(`${API_URL}/user/delete-self`, { 
                    method: 'POST', 
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ user_id: currentUser.id }) // Envia o ID do usuário logado
                });
                
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Não foi possível excluir a conta.');
                
                confirmationModal.hide();
                alert(data.message || 'Conta excluída/anonimizada com sucesso.');
                
                // Faz o logout completo do usuário
                performFullLogout(); 
                
            } catch (err) {
                alert(err.message);
            }
        }, { once: true });

        confirmationModal.show();
    }


    // --- DASHBOARD (TAREFAS) ---
    async function renderDashboardView() {
        const searchContainer = document.getElementById('header-search-container');
        searchContainer.style.display = 'block';
        searchContainer.innerHTML = `<input type="search" id="task-search-input" class="form-control" placeholder="🔍 Buscar tarefas...">`;
        document.getElementById('task-search-input').addEventListener('input', renderTasks);
        
        // Define se botões de admin (criar/editar/excluir) devem estar ativos
        // NÃO DEVEM estar ativos se estiver impersonando.
        const isAdminView = (currentUser.role === 'admin' && !currentUser.impersonating);

        mainContent.innerHTML = `
            <div class="content-header">
                <h2>Dashboard de Tarefas</h2>
                <div class="task-filters btn-group" role="group">
                    <button type="button" class="btn btn-outline-primary active" data-filter="all">Todas</button>
                    <button type="button" class="btn btn-outline-primary" data-filter="mine">Minhas Tarefas</button>
                    <button type="button" class="btn btn-outline-primary" data-filter="overdue">Atrasadas</button>
                </div>
            </div>
            <div id="add-task-card" class="card my-4" style="display: ${isAdminView ? 'block' : 'none'}">
                <div class="card-header bg-white py-3"><h5 class="mb-0 fw-bold">Adicionar Nova Tarefa</h5></div>
                <div class="card-body p-4"><form id="task-form"></form></div>
            </div>
            <div id="task-list" class="row gy-4"></div>`;

        mainContent.querySelector('.task-filters').addEventListener('click', handleFilterClick);
        const taskForm = mainContent.querySelector('#task-form');
        if (taskForm) {
            taskForm.innerHTML = `<div class="row g-3"><div class="col-md-6"><label class="form-label">Título</label><input type="text" id="task-title" class="form-control" required></div>
            <div class="col-md-3"><label class="form-label">Prioridade</label><select id="task-priority" class="form-select"><option value="3">Baixa</option><option value="2" selected>Média</option><option value="1">Alta</option></select></div>
            <div class="col-md-3"><label class="form-label">Prazo</label><input type="date" id="task-due-date" class="form-control"></div>
            <div class="col-12"><label class="form-label">Descrição</label><textarea id="task-description" class="form-control" rows="3" required></textarea></div>
            <div class="col-12" style="display: ${isAdminView ? 'block' : 'none'}"><label class="form-label">Atribuir para:</label><select id="assign-to" class="form-select"><option value="">Ninguém</option></select></div>
            <div class="col-12 text-end"><button type="submit" class="btn btn-success fw-semibold px-4">Salvar Tarefa</button></div></div>`;
            if (isAdminView) await populateAssigneeDropdown(taskForm.querySelector('#assign-to'));
            taskForm.addEventListener('submit', handleAddTask);
        }

        mainContent.querySelector('#task-list').addEventListener('click', handleTaskListClick);
        initializeModalsAndChat();
        fetchAndRenderTasks();
    }

    // --- ANALYTICS VIEW ---
    async function renderAnalyticsView() {
        mainContent.innerHTML = `
            <div class="content-header"><h2>Análise de Desempenho</h2></div>
            <div id="analytics-grid" class="analytics-grid">
                <div class="text-center p-5"><div class="spinner-border text-primary" role="status"></div></div>
            </div>`;
        try {
            const response = await fetch(`${API_URL}/analytics`);
            if (!response.ok) throw new Error('Não foi possível carregar os dados de análise.');
            const data = await response.json();
            document.getElementById('analytics-grid').innerHTML = `
                <div class="stat-card"><i class="bi bi-stack"></i><div class="stat-number">${data.totalTasks}</div><div class="stat-title">Total de Tarefas</div></div>
                <div class="stat-card"><i class="bi bi-hourglass-split" style="color: #ffc107;"></i><div class="stat-number">${data.pendingTasks}</div><div class="stat-title">Tarefas Pendentes</div></div>
                <div class="stat-card"><i class="bi bi-check2-circle" style="color: #198754;"></i><div class="stat-number">${data.completedTasks}</div><div class="stat-title">Tarefas Concluídas</div></div>
                <div class="stat-card"><i class="bi bi-calendar-x" style="color: #dc3545;"></i><div class="stat-number">${data.overdueTasks}</div><div class="stat-title">Tarefas Atrasadas</div></div>
                <div class="stat-card col-span-2"><i class="bi bi-person-check-fill" style="color: #0dcaf0;"></i><div class="stat-number">${data.topUser.username}</div><div class="stat-title">Top Funcionário (${data.topUser.task_count} tarefas)</div></div>`;
        } catch (error) {
             document.getElementById('analytics-grid').innerHTML = `<p class="text-danger">${error.message}</p>`;
        }
    }

    // --- TEAM VIEW ---
    async function renderTeamView() {
        mainContent.innerHTML = `
            <div class="content-header"><h2>Membros da Equipe</h2></div>
            <div id="team-list" class="team-grid"><div class="text-center p-5"><div class="spinner-border text-primary" role="status"></div></div></div>`;
        try {
            const response = await fetch(`${API_URL}/users/employees`);
            if (!response.ok) throw new Error('Não foi possível carregar a lista de funcionários.');
            const employees = await response.json();
            const listEl = document.getElementById('team-list');
            listEl.innerHTML = '';
            if (employees.length === 0) { listEl.innerHTML = '<p class="text-muted">Nenhum funcionário encontrado.</p>'; return; }
            employees.forEach(emp => {
                listEl.innerHTML += `<div class="team-card"><div class="team-card-icon"><i class="bi bi-person"></i></div><div class="team-card-info"><p class="name">${emp.username}</p><p class="title">${emp.job_title || 'Funcionário'}</p><p class="email">${emp.email}</p></div></div>`;
            });
        } catch (error) {
            document.getElementById('team-list').innerHTML = `<p class="text-danger">${error.message}</p>`;
        }
    }
    
    // --- ACTIVITY LOG VIEW ---
    async function renderActivityLogView() {
        mainContent.innerHTML = `
            <div class="content-header">
                <h2>Log de Atividades do Sistema</h2>
            </div>
            <div class="card">
                <div class="card-body">
                    <div id="activity-log-container" class="table-responsive">
                        <div class="text-center p-5"><div class="spinner-border text-primary" role="status"></div></div>
                    </div>
                </div>
            </div>`;
        
        try {
            const response = await fetch(`${API_URL}/activity-log`);
            if (!response.ok) throw new Error('Não foi possível carregar o log de atividades.');
            const logs = await response.json();
            
            const container = document.getElementById('activity-log-container');
            if (logs.length === 0) {
                container.innerHTML = '<p class="text-muted text-center">Nenhuma atividade registrada.</p>';
                return;
            }
            
            let tableHtml = `
                <table class="table table-striped table-hover activity-log-table">
                    <thead class="table-light">
                        <tr>
                            <th scope="col">Usuário</th>
                            <th scope="col">Ação</th>
                            <th scope="col">Data e Hora</th>
                        </tr>
                    </thead>
                    <tbody>`;
            
            logs.forEach(log => {
                const timestamp = new Date(log.timestamp).toLocaleString('pt-BR');
                tableHtml += `
                    <tr>
                        <td><strong>${log.username || '[desconhecido]'}</strong></td>
                        <td>${log.action_text}</td>
                        <td class="text-muted small">${timestamp}</td>
                    </tr>`;
            });
            
            tableHtml += `</tbody></table>`;
            container.innerHTML = tableHtml;
            
        } catch (error) {
            document.getElementById('activity-log-container').innerHTML = `<p class="text-danger">${error.message}</p>`;
        }
    }
    
    // --- ================================== ---
    // --- NOVA VIEW: SSAP (User Management) ---
    // --- ================================== ---
    async function renderSSAPView() {
        mainContent.innerHTML = `
            <div class="content-header">
                <h2>Gerenciamento de Usuários (SSAP)</h2>
            </div>
            <div class="card">
                <div class="card-body">
                    <div id="user-management-container" class="table-responsive">
                        <div class="text-center p-5"><div class="spinner-border text-primary" role="status"></div></div>
                    </div>
                </div>
            </div>`;
            
        try {
            const response = await fetch(`${API_URL}/admin/users?admin_user_id=${currentUser.id}`);
            if (!response.ok) throw new Error((await response.json()).error || 'Não foi possível carregar os usuários.');
            const users = await response.json();
            
            const container = document.getElementById('user-management-container');
            if (users.length === 0) {
                container.innerHTML = '<p class="text-muted text-center">Nenhum usuário encontrado.</p>';
                return;
            }

            let tableHtml = `
                <table class="table table-hover user-management-table">
                    <thead class="table-light">
                        <tr>
                            <th scope="col">Usuário</th>
                            <th scope="col">E-mail</th>
                            <th scope="col">Cargo</th>
                            <th scope="col">Role</th>
                            <th scope="col" class="text-end">Ações</th>
                        </tr>
                    </thead>
                    <tbody>`;
            
            users.forEach(user => {
                const isCurrentUser = user.id === currentUser.id;
                const roleBadge = user.role === 'admin' 
                    ? `<span class="badge bg-primary role-badge">Admin</span>` 
                    : `<span class="badge bg-secondary role-badge">Funcionário</span>`;
                
                // Desabilita botões de ação para o próprio admin
                const actions = isCurrentUser ? '<span class="text-muted small">Não é possível alterar a si mesmo</span>' : `
                    <button class="btn btn-sm btn-outline-secondary" title="Impersonar" data-action="impersonate" data-id="${user.id}" data-username="${user.username}"><i class="bi bi-person-fill-gear"></i> Impersonar</button>
                    <button class="btn btn-sm btn-outline-primary" title="Editar" data-action="edit" data-id="${user.id}"><i class="bi bi-pencil"></i></button>
                    <button class="btn btn-sm btn-outline-warning" title="Forçar Reset de Senha" data-action="reset" data-id="${user.id}" data-username="${user.username}"><i class="bi bi-key-fill"></i></button>
                    <button class="btn btn-sm btn-outline-danger" title="Excluir" data-action="delete" data-id="${user.id}" data-username="${user.username}"><i class="bi bi-trash"></i></button>
                `;
                
                tableHtml += `
                    <tr>
                        <td><strong>${user.username}</strong> ${user.needs_password_reset ? '<span class="badge bg-warning text-dark">Reset Pendente</span>' : ''}</td>
                        <td>${user.email || 'N/A'}</td>
                        <td>${user.job_title || 'N/A'}</td>
                        <td>${roleBadge}</td>
                        <td class="actions-cell">${actions}</td>
                    </tr>`;
            });
            
            tableHtml += `</tbody></table>`;
            container.innerHTML = tableHtml;
            
            // Adiciona event listeners para os botões da tabela
            container.addEventListener('click', (e) => {
                const button = e.target.closest('button[data-action]');
                if (!button) return;
                
                const action = button.dataset.action;
                const userId = parseInt(button.dataset.id);
                const username = button.dataset.username;

                if (action === 'delete') handleAdminDeleteUser(userId, username);
                if (action === 'reset') handleAdminForceReset(userId, username);
                if (action === 'edit') handleAdminOpenEditModal(userId);
                if (action === 'impersonate') handleAdminImpersonate(userId, username);
            });
            
        } catch (error) {
            document.getElementById('user-management-container').innerHTML = `<p class="text-danger text-center">${error.message}</p>`;
        }
    }


    // --- RENDERIZAÇÃO DAS TAREFAS ---
    function renderTasks() {
        const searchTerm = document.getElementById('task-search-input')?.value.toLowerCase() || '';
        const filteredBySearch = allTasks.filter(task => (task.title || '').toLowerCase().includes(searchTerm) || (task.description || '').toLowerCase().includes(searchTerm));
        const tasksToRender = filteredBySearch.filter(task => {
            if (currentFilter === 'mine') return task.assigned_to_id === currentUser.id;
            if (currentFilter === 'overdue') return !task.completed && task.due_date && new Date(task.due_date) < new Date();
            return true;
        });
        const taskList = mainContent.querySelector('#task-list');
        if (!taskList) return;
        taskList.innerHTML = tasksToRender.length === 0 ? '<p class="text-center text-muted">Nenhuma tarefa encontrada.</p>' : '';
        
        // Define se botões de admin (editar/excluir) devem estar visíveis
        const isAdminView = (currentUser.role === 'admin' && !currentUser.impersonating);
        
        tasksToRender.forEach(task => {
            const priority = {1:{bg:'danger',txt:'Alta'}, 2:{bg:'warning',txt:'Média'}, 3:{bg:'success',txt:'Baixa'}}[task.priority] || {bg:'secondary', txt:'Média'};
            const isOverdue = !task.completed && task.due_date && new Date(task.due_date) < new Date();
            
            // ATUALIZADO: Mostra botões de admin apenas se for admin E não estiver impersonando
            const adminButtons = isAdminView
                ? `<button class="btn btn-outline-secondary" title="Editar" data-action="edit" data-id="${task.id}"><i class="bi bi-pencil"></i></button><button class="btn btn-outline-danger" title="Excluir" data-action="delete" data-id="${task.id}"><i class="bi bi-trash"></i></button>`
                : '';
                
            const card = document.createElement('div');
            card.className = 'col-md-6 col-lg-4';
            const completedStr = task.completed ? 'true' : 'false';
            
            const createdAtStr = task.created_at ? new Date(task.created_at).toLocaleString('pt-BR') : 'N/A';
            
            // O botão de concluir/reabrir fica desabilitado durante a impersonação?
            // Decisão: Não, o usuário impersonado (ex: funcionário) deve poder concluir suas próprias tarefas.
            // Mas se for admin impersonando, ele não deve poder editar/excluir.
            
            card.innerHTML = `
                <div class="card h-100 task-card ${task.completed ? 'completed-task' : ''}">
                    <div class="task-actions">
                        ${adminButtons}
                        <button class="btn btn-outline-info" title="Comentários" data-action="comments" data-id="${task.id}"><i class="bi bi-chat-left-text"></i></button>
                        <button class="${task.completed ? 'btn btn-outline-secondary' : 'btn btn-success'}" title="${task.completed ? 'Reabrir' : 'Concluir'}" data-action="toggle-complete" data-id="${task.id}" data-completed="${completedStr}">
                            <i class="bi ${task.completed ? 'bi-x-lg' : 'bi-check-lg'}"></i>
                        </button>
                    </div>
                    <div class="card-body">
                        <div class="d-flex justify-content-between">
                            <h5 class="card-title">${task.title}</h5>
                            <span class="badge bg-${priority.bg}-subtle text-${priority.bg}-emphasis p-2">${priority.txt}</span>
                        </div>
                        <p class="card-text text-muted small">${task.description || ''}</p>
                        <div class="small text-muted"><b>Prazo:</b> ${task.due_date ? new Date(task.due_date).toLocaleDateString('pt-BR', { timeZone: 'UTC' }) : 'N/A'} ${isOverdue ? '<span class="badge bg-danger ms-2">Atrasada</span>' : ''}</div>
                        <div class="small text-muted mt-1"><b>Para:</b> ${task.assignee_name || 'Ninguém'}</div>
                        <div class="small text-muted mt-3"><b>Criado por:</b> ${task.creator_name || 'N/A'}</div>
                        <div class="small text-muted mt-1"><b>Criado em:</b> ${createdAtStr}</div>
                    </div>
                </div>`;
            taskList.appendChild(card);
        });
    }

    // --- MODAIS / CHAT / HELPERS (inicialização) ---
    function initializeModalsAndChat() {
        if (!editTaskModal) {
            const el = document.getElementById('editTaskModal');
            el.innerHTML = `<div class="modal-dialog modal-lg"><div class="modal-content"><div class="modal-header"><h5 class="modal-title">Editar Tarefa</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="edit-task-form"></form></div><div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button><button type="submit" form="edit-task-form" class="btn btn-primary">Salvar</button></div></div></div>`;
            editTaskModal = new bootstrap.Modal(el);
            el.querySelector('#edit-task-form').addEventListener('submit', handleEditTask);
        }
        // NOVO MODAL: Admin User Edit
        if (!adminUserEditModal) {
            const el = document.getElementById('adminUserEditModal');
            // O conteúdo é populado dinamicamente, mas o modal é inicializado
            adminUserEditModal = new bootstrap.Modal(el);
            el.querySelector('#admin-user-edit-form').addEventListener('submit', handleAdminEditUser);
        }
        if (!commentsModal) {
            const el = document.getElementById('commentsModal');
            el.innerHTML = `<div class="modal-dialog modal-dialog-centered"><div class="modal-content"><div class="modal-header"><h5 class="modal-title">Comentários</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><div id="comments-list" class="mb-3" style="max-height: 400px; overflow-y: auto;"></div><form id="comment-form"><input type="hidden" id="comment-task-id"><div class="input-group"><input type="text" id="comment-input" class="form-control" placeholder="Adicionar comentário..." required autocomplete="off"><button class="btn btn-outline-primary" type="submit">Enviar</button></div></form></div></div></div>`;
            commentsModal = new bootstrap.Modal(el);
            el.querySelector('#comment-form').addEventListener('submit', handleAddComment);
        }
        if (!confirmationModal) {
            const el = document.getElementById('confirmationModal');
            // Conteúdo já está no HTML, apenas inicializa
            confirmationModal = new bootstrap.Modal(el);
        }

        const chat = document.getElementById('chat-container');
        if (!chat.innerHTML.trim()) {
            chat.innerHTML = `
                <div id="chat-bubble"><i class="bi bi-chat-dots-fill"></i></div>
                <div id="chat-window">
                    <div class="chat-header">Chat da Equipe</div>
                    <div id="chat-messages"></div>
                    <form id="chat-form">
                        <input type="text" id="chat-input" class="form-control" placeholder="Digite sua mensagem..." autocomplete="off">
                        <button type="submit" class="btn btn-primary ms-2"><i class="bi bi-send-fill"></i></button>
                    </form>
                </div>`;

            const chatBubble = chat.querySelector('#chat-bubble');
            const chatWindow = document.getElementById('chat-window');

            chatBubble.addEventListener('click', async () => {
                const isOpen = window.getComputedStyle(chatWindow).display === 'flex';
                chatWindow.style.display = isOpen ? 'none' : 'flex';

                if (!isOpen) {
                    try {
                        await renderChatMessages();
                    } catch (err) {
                        console.error('Erro ao carregar mensagens do chat:', err);
                    }
                }
            });
            chat.querySelector('#chat-form').addEventListener('submit', handleSendChatMessage);
        }
    }


    // --- UTIL: popula dropdown de responsáveis ---
    async function populateAssigneeDropdown(selectElement) {
        try {
            const res = await fetch(`${API_URL}/users/employees`);
            if (!res.ok) throw new Error('Falha ao buscar funcionários');
            const employees = await res.json();
            selectElement.innerHTML = '<option value="">Ninguém</option>';
            employees.forEach(emp => selectElement.innerHTML += `<option value="${emp.id}">${emp.username}</option>`);
        } catch (error) {
            console.error(error.message);
        }
    }

    function handleFilterClick(e) {
        if (e.target.tagName === 'BUTTON') {
            mainContent.querySelector('.task-filters .active').classList.remove('active');
            e.target.classList.add('active');
            currentFilter = e.target.dataset.filter;
            renderTasks();
        }
    }

    // --- BUSCA E RENDERIZAÇÃO DAS TAREFAS (faz fetch e popula allTasks) ---
    async function fetchAndRenderTasks() {
        try {
            const res = await fetch(`${API_URL}/tasks`);
            if (!res.ok) throw new Error('Falha ao carregar tarefas');
            allTasks = await res.json();
            renderTasks();
        } catch (error) {
            const list = mainContent.querySelector('#task-list');
            if (list) list.innerHTML = `<p class="text-center text-danger">${error.message}</p>`;
        }
    }

    // --- CLICK HANDLER GERAL PARA OS BOTOES DENTRO DA LISTA ---
    function handleTaskListClick(e) {
        const button = e.target.closest('button[data-action]');
        if (!button) return;
        
        // Se estiver impersonando, desabilita ações de admin
        if (currentUser.impersonating && (button.dataset.action === 'edit' || button.dataset.action === 'delete')) {
            alert('Ações de administrador estão desabilitadas durante a impersonação.');
            return;
        }
        
        const action = button.dataset.action;
        const taskId = parseInt(button.dataset.id);
        const actions = {
            'edit': () => handleOpenEditModal(taskId),
            'delete': () => handleDeleteTask(taskId),
            'comments': () => handleOpenCommentsModal(taskId),
            'toggle-complete': () => handleToggleComplete(taskId)
        };
        if (actions[action]) actions[action]();
    }

    async function handleAddTask(e) {
        e.preventDefault();
        const assigneeId = document.getElementById('assign-to').value;
        const taskData = {
            title: document.getElementById('task-title').value,
            description: document.getElementById('task-description').value,
            priority: parseInt(document.getElementById('task-priority').value),
            due_date: document.getElementById('task-due-date').value || null,
            creator_id: currentUser.id, // O criador é sempre o usuário logado (o admin)
            assigned_to_id: assigneeId ? parseInt(assigneeId) : null
        };
        try {
            const res = await fetch(`${API_URL}/tasks`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(taskData)
            });
            if (!res.ok) throw new Error((await res.json()).error || 'Erro ao criar tarefa');
            e.target.reset();
            fetchAndRenderTasks();
        } catch (error) {
            alert(`Erro: ${error.message}`);
        }
    }

    async function handleEditTask(e) {
        e.preventDefault();
        const form = e.target;
        const taskId = parseInt(form.dataset.taskId);
        const assigneeId = form.elements['edit-assign-to'].value;
        const taskData = {
            title: form.elements['edit-task-title'].value,
            description: form.elements['edit-task-description'].value,
            priority: parseInt(form.elements['edit-task-priority'].value),
            due_date: form.elements['edit-task-due-date'].value || null,
            assigned_to_id: assigneeId ? parseInt(assigneeId) : null,
            acting_user_id: currentUser.id // Envia quem está fazendo a ação
        };
        try {
            const res = await fetch(`${API_URL}/tasks/${taskId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(taskData)
            });
            if (!res.ok) throw new Error((await res.json()).error || 'Erro ao editar tarefa');
            editTaskModal.hide();
            fetchAndRenderTasks();
        } catch (error) {
            alert(`Erro: ${error.message}`);
        }
    }

    async function handleToggleComplete(taskId) {
        try {
            let task = allTasks.find(t => t.id === taskId);
            if (!task) {
                const resTask = await fetch(`${API_URL}/tasks/${taskId}`);
                if (!resTask.ok) throw new Error('Não foi possível obter o estado da tarefa.');
                task = await resTask.json();
            }

            const currentCompleted = !!task.completed;
            const payload = { 
                completed: !currentCompleted,
                // ATUALIZADO: Envia quem está fazendo a ação
                // Se estiver impersonando, a ação é logada como o usuário impersonado
                acting_user_id: currentUser.id 
            };
            
            const res = await fetch(`${API_URL}/tasks/${taskId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) throw new Error(data.error || data.message || 'Erro ao alternar conclusão');
            await fetchAndRenderTasks();
        } catch (error) {
            alert(`Erro: ${error.message}`);
        }
    }

    function handleDeleteTask(taskId) {
        const confirmationText = 'Tem certeza que deseja excluir esta tarefa? Esta ação não pode ser desfeita.';
        
        // Reusa o modal de confirmação
        document.getElementById('confirmation-modal-body').textContent = confirmationText;
        const confirmBtn = document.getElementById('confirm-action-btn');
        
        // Clona para remover listeners antigos
        const newConfirmBtn = confirmBtn.cloneNode(true);
        confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);

        newConfirmBtn.addEventListener('click', async () => {
            try {
                const res = await fetch(`${API_URL}/tasks/${taskId}`, { 
                    method: 'DELETE', 
                    headers: { 'Content-Type': 'application/json' },
                    // ATUALIZADO: Envia quem está fazendo a ação
                    body: JSON.stringify({ acting_user_id: currentUser.id })
                });
                let data;
                try { data = await res.json(); } catch (e) { data = {}; }
                if (!res.ok) {
                    alert(data.error || data.message || 'Não foi possível excluir a tarefa.');
                    return;
                }
                confirmationModal.hide();
                fetchAndRenderTasks();
                // alert(data.message || 'Tarefa excluída com sucesso.'); // Opcional
            } catch (err) {
                alert('Erro ao conectar com o servidor.');
            }
        }, { once: true }); // Garante que o listener rode só uma vez

        confirmationModal.show();
    }

    async function handleOpenEditModal(taskId) {
        try {
            const res = await fetch(`${API_URL}/tasks/${taskId}`);
            if (!res.ok) throw new Error('Não foi possível carregar os dados da tarefa.');
            const task = await res.json();
            const form = document.getElementById('edit-task-form');
            form.dataset.taskId = taskId;
            form.innerHTML = `<div class="row g-3">
                <div class="col-12"><label class="form-label">Título</label><input type="text" id="edit-task-title" class="form-control" value="${task.title}" required></div>
                <div class="col-md-6"><label class="form-label">Prioridade</label><select id="edit-task-priority" class="form-select"></select></div>
                <div class="col-md-6"><label class="form-label">Prazo</label><input type="date" id="edit-task-due-date" class="form-control" value="${task.due_date ? task.due_date.split('T')[0] : ''}"></div>
                <div class="col-12"><label class="form-label">Descrição</label><textarea id="edit-task-description" class="form-control" rows="3" required>${task.description || ''}</textarea></div>
                <div class="col-12"><label class="form-label">Atribuir para:</label><select id="edit-assign-to" class="form-select"><option value="">Ninguém</option></select></div>
            </div>`;
            const prioritySelect = form.elements['edit-task-priority'];
            prioritySelect.innerHTML = `<option value="1">Alta</option><option value="2">Média</option><option value="3">Baixa</option>`;
            prioritySelect.value = task.priority;
            const assigneeSelect = form.elements['edit-assign-to'];
            await populateAssigneeDropdown(assigneeSelect);
            assigneeSelect.value = task.assigned_to_id || "";
            editTaskModal.show();
        } catch (error) {
            alert(error.message);
        }
    }

    // --- ======================================== ---
    // --- NOVAS FUNÇÕES (SSAP User Management) ---
    // --- ======================================== ---

    function handleAdminDeleteUser(userId, username) {
        const confirmationText = `Tem certeza que deseja EXCLUIR permanentemente o usuário '${username}'? Esta ação não pode ser desfeita e removerá o usuário do sistema.`;
        
        document.getElementById('confirmation-modal-body').textContent = confirmationText;
        const confirmBtn = document.getElementById('confirm-action-btn');
        
        const newConfirmBtn = confirmBtn.cloneNode(true);
        confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);

        newConfirmBtn.addEventListener('click', async () => {
            try {
                const res = await fetch(`${API_URL}/admin/user/${userId}`, { 
                    method: 'DELETE', 
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ admin_user_id: currentUser.id })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Não foi possível excluir o usuário.');
                
                confirmationModal.hide();
                alert(data.message || 'Usuário excluído com sucesso.');
                renderView('ssap'); // Recarrega a view
            } catch (err) {
                alert(err.message);
            }
        }, { once: true });

        confirmationModal.show();
    }

    function handleAdminForceReset(userId, username) {
        const confirmationText = `Tem certeza que deseja FORÇAR UMA REDEFINIÇÃO DE SENHA para '${username}'? O usuário será obrigado a criar uma nova senha no próximo login.`;
        
        document.getElementById('confirmation-modal-body').textContent = confirmationText;
        const confirmBtn = document.getElementById('confirm-action-btn');
        
        const newConfirmBtn = confirmBtn.cloneNode(true);
        confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);

        newConfirmBtn.addEventListener('click', async () => {
            try {
                const res = await fetch(`${API_URL}/admin/force-reset-password`, { 
                    method: 'POST', 
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        admin_user_id: currentUser.id,
                        target_user_id: userId
                    })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Não foi possível resetar a senha.');
                
                confirmationModal.hide();
                // MELHORIA LGPD: Não mostra a nova senha no alert, apenas a msg de sucesso.
                alert(data.message); 
                renderView('ssap'); // Recarrega a view
            } catch (err) {
                alert(err.message);
            }
        }, { once: true });

        confirmationModal.show();
    }

    async function handleAdminOpenEditModal(userId) {
        try {
            const res = await fetch(`${API_URL}/user/${userId}`);
            if (!res.ok) throw new Error('Não foi possível carregar os dados do usuário.');
            const user = await res.json();
            
            const form = document.getElementById('admin-user-edit-form');
            form.dataset.targetUserId = userId; // Armazena o ID do usuário sendo editado
            form.innerHTML = `<div class="row g-3">
                <div class="col-md-6">
                    <label class="form-label">Nome de Usuário</label>
                    <input type="text" id="admin-edit-username" class="form-control" value="${user.username}" required>
                </div>
                <div class="col-md-6">
                    <label class="form-label">E-mail</label>
                    <input type="email" id="admin-edit-email" class="form-control" value="${user.email || ''}" required>
                </div>
                <div class="col-md-6">
                    <label class="form-label">Cargo</label>
                    <input type="text" id="admin-edit-job-title" class="form-control" value="${user.job_title || ''}">
                </div>
                <div class="col-md-6">
                    <label class="form-label">Role (Permissão)</label>
                    <select id="admin-edit-role" class="form-select">
                        <option value="funcionario">Funcionário</option>
                        <option value="admin">Administrador</option>
                    </select>
                </div>
                <div id="admin-user-edit-error" class="error-message"></div>
            </div>`;
            
            form.elements['admin-edit-role'].value = user.role;
            adminUserEditModal.show();
        } catch (error) {
            alert(error.message);
        }
    }

    async function handleAdminEditUser(e) {
        e.preventDefault();
        const form = e.target;
        const targetUserId = parseInt(form.dataset.targetUserId);
        const errorEl = document.getElementById('admin-user-edit-error');
        errorEl.textContent = '';
        
        const updatedData = {
            username: form.elements['admin-edit-username'].value.trim(),
            email: form.elements['admin-edit-email'].value.trim(),
            job_title: form.elements['admin-edit-job-title'].value.trim(),
            role: form.elements['admin-edit-role'].value,
            acting_user_id: currentUser.id // O admin que está fazendo a ação
        };
        
        try {
            const response = await fetch(`${API_URL}/user/${targetUserId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(updatedData)
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || 'Erro ao atualizar usuário');
            
            adminUserEditModal.hide();
            renderView('ssap'); // Recarrega a lista de usuários
        } catch (error) {
            errorEl.textContent = error.message;
        }
    }

    async function handleAdminImpersonate(targetUserId, username) {
        const confirmationText = `Você está prestes a "impersonar" o usuário '${username}'. Você verá o sistema exatamente como ele vê e suas ações serão registradas como se fossem dele. Deseja continuar?`;
        
        if (!confirm(confirmationText)) return;

        try {
            // 1. Salva a sessão do admin atual no localStorage
            localStorage.setItem('originalAdminSession', JSON.stringify(currentUser));
            
            // 2. Solicita um token de impersonação ao backend
            const resToken = await fetch(`${API_URL}/admin/impersonate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    admin_user_id: currentUser.id,
                    target_user_id: targetUserId
                })
            });
            const dataToken = await resToken.json();
            if (!resToken.ok) throw new Error(dataToken.error || 'Falha ao iniciar impersonação');
            
            // 3. Usa o token para "logar" como o usuário alvo
            const resLogin = await fetch(`${API_URL}/impersonate/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: dataToken.token })
            });
            const dataLogin = await resLogin.json();
            if (!resLogin.ok) throw new Error(dataLogin.error || 'Falha ao logar como usuário');
            
            // 4. Inicia a nova sessão com os dados do usuário impersonado
            startSession(dataLogin.user);
            
        } catch (error) {
            alert(`Erro na impersonação: ${error.message}`);
            // Limpa o backup da sessão do admin se a impersonação falhar
            localStorage.removeItem('originalAdminSession');
        }
    }


    // --- Handlers de Comentários (Sem alterações) ---
    async function handleOpenCommentsModal(taskId) {
        document.getElementById('comment-task-id').value = taskId;
        await renderComments(taskId);
        commentsModal.show();
    }
    async function renderComments(taskId) {
        try {
            const res = await fetch(`${API_URL}/tasks/${taskId}/comments`);
            if (!res.ok) throw new Error('Não foi possível carregar os comentários.');
            const comments = await res.json();
            const listEl = document.getElementById('comments-list');
            listEl.innerHTML = comments.length === 0 ? '<p class="text-muted text-center">Nenhum comentário ainda.</p>' : '';
            comments.forEach(c => listEl.innerHTML += `<div class="comment"><p class="mb-1"><strong>${c.username}:</strong> ${c.text}</p><small class="text-muted">${new Date(c.timestamp).toLocaleString('pt-BR')}</small></div>`);
            listEl.scrollTop = listEl.scrollHeight;
        } catch (error) {
            alert(error.message);
        }
    }
    async function handleAddComment(e) {
        e.preventDefault();
        const taskId = parseInt(document.getElementById('comment-task-id').value);
        const text = document.getElementById('comment-input').value.trim();
        if (!text) return;
        try {
            const res = await fetch(`${API_URL}/tasks/${taskId}/comments`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: currentUser.id, text }) // Ação logada como usuário atual (mesmo se impersonado)
            });
            if (!res.ok) throw new Error((await res.json()).error || 'Erro ao adicionar comentário');
            document.getElementById('comment-input').value = '';
            await renderComments(taskId);
            await fetchAndRenderTasks();
        } catch (error) {
            alert(`Erro: ${error.message}`);
        }
    }

    // --- Handlers de Chat (Sem alterações) ---
    async function handleSendChatMessage(e) {
        e.preventDefault();
        const input = document.getElementById('chat-input');
        const text = input.value.trim();
        if (!text) return;
        try {
            const res = await fetch(`${API_URL}/chat/messages`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: currentUser.id, text }) // Ação logada como usuário atual
            });
            if (!res.ok) throw new Error((await res.json()).error || 'Erro ao enviar mensagem');
            input.value = '';
            await renderChatMessages();
        } catch (error) {
            alert(`Erro: ${error.message}`);
        }
    }

    async function renderChatMessages() {
        try {
            const res = await fetch(`${API_URL}/chat/messages`);
            if (!res.ok) throw new Error('Não foi possível carregar mensagens do chat.');
            const messages = await res.json();
            const messagesEl = document.getElementById('chat-messages');
            messagesEl.innerHTML = '';
            messages.forEach(msg => messagesEl.innerHTML += `<div class="p-2"><strong>${msg.username}:</strong> ${msg.text}</div>`);
            messagesEl.scrollTop = messagesEl.scrollHeight;
        } catch (error) {
            alert(error.message);
        }
    }
    
});
