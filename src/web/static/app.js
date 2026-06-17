// ===== MuccheAI Web UI =====
const API = (window.location.port === '8888') ? 'http://127.0.0.1:3000' : '';
const THEME_CSS_VERSION = '12';
const APP_JS_VERSION = '48';
let token = ''; // Auth disabled — no login required
let csrfToken = localStorage.getItem('csrf_token') || '';
let currentTheme = localStorage.getItem('theme') || 'dark-chat';
let aiName = localStorage.getItem('aiName') || 'MuccheAI';

const THINKING_WORDS = [
  'Riflettendo', 'Sintetizzando', 'Ragionando', 'Analizzando', 'Valutando',
  'Contemplando', 'Formulando', 'Inferendo', 'Ponderando', 'Deliberando',
  'Esaminando', 'Costruendo', 'Distillando', 'Interpretando', 'Verificando',
  'Affinando', 'Confrontando', 'Immaginando', 'Soppesando', 'Elaborando',
  'Processando', 'Decodificando', 'Calibrando', 'Compilando', 'Contextualizzando',
  'Definendo', 'Derivando', 'Sviluppando', 'Espandendo', 'Estratto',
  'Filtrando', 'Generalizzando', 'Ipotizzando', 'Integrando', 'Mappando',
  'Modellando', 'Navigando', 'Osservando', 'Ottimizzando', 'Parsing',
  'Penetrando', 'Pianificando', 'Precisando', 'Progettando', 'Prospettando',
  'Quantificando', 'Raccogliendo', 'Rianalizzando', 'Ricapitolando', 'Ricollegando',
  'Riformulando', 'Risolvendo', 'Ruminatione', 'Scansionando', 'Scrutando',
  'Selezionando', 'Sondando', 'Stratificando', 'Strutturando', 'Tessendo',
  'Traslando', 'Unificando', 'Valicando', 'Verbalizzando', 'Visionando',
  'Abbinando', 'Accertando', 'Approfondendo', 'Argomentando', 'Arricchendo',
  'Assimilando', 'Categorizzando', 'Circoscrivere', 'Coagulando', 'Collazionando',
  'Concretizzando', 'Coniugando', 'Correlando', 'Decifrando', 'Delineando',
  'Differentiando', 'Discernendo', 'Dissezionando', 'Estrapolando', 'Focalizzando',
  'Giustapporre', 'Indagando', 'Mediazione', 'Mettendo a fuoco', 'Ordinando',
  'Ponderazione', 'Raffinando', 'Ricalibrando', 'Ricostruendo', 'Rileggendo',
  'Rinormalizzando', 'Risistemando', 'Rivedendo', 'Schematizzando', 'Scomporre',
  'Sintetizzazione', 'Sommando', 'Sottolineando', 'Specificando', 'Trasformando'
];
let thinkingWordInterval = null;

// ===== i18n =====
const TRANSLATIONS = {
  en: {
    newChat: 'New chat',
    send: 'Send',
    messagePlaceholder: 'Message {{name}}...',
    searchChats: 'Search chats',
    history: 'History',
    status: 'Status',
    agents: 'Agents',
    tools: 'Tools',
    memory: 'Memory',
    system: 'System',
    graph: 'Graph',
    settings: 'Settings',
    tasks: 'Scheduled Tasks',
    research: 'Research Chats',
    welcome: 'Welcome to {{name}}',
    offline: 'You are offline — messages will be queued',
    thinking: 'Thinking...',
    noChats: 'No chats yet',
    noMemories: 'No memories yet',
    noTasks: 'No scheduled tasks yet.',
    noTools: 'No custom tools yet.',
    language: 'Language',
    aiName: 'AI Name',
    model: 'Model',
    temperature: 'Temperature',
    maxTokens: 'Max tokens',
    save: 'Save',
    cancel: 'Cancel',
    remove: 'Remove',
    newDatabaseName: 'New database name',
    delete: 'Delete',
    edit: 'Edit',
    copy: 'Copy',
    regenerate: 'Regenerate',
    share: 'Share',
    encryptShare: 'Encrypted Share',
    close: 'Close',
    listening: 'Listening...',
    toastSessionExpired: 'Session expired. Please log in again.',
    toastNoSessionToShare: 'No active session to share. Send a message first.',
    toastShareCopied: 'Session link copied to clipboard',
    toastShareFailed: 'Share failed: {{error}}',
    toastTaskScheduled: 'Task scheduled',
    toastTaskDeleted: 'Task deleted',
    toastToolCreated: 'Tool created',
    toastToolDeleted: 'Tool deleted',
    toastMemorySaved: 'Memory saved',
    toastSettingsSaved: 'Settings saved',
    toastFailed: 'Failed: {{error}}',
    rag: 'RAG System',
    ragDescription: 'Retrieval-Augmented Generation lets MuccheAI search your documents before answering.',
    ragHowItWorks: 'How it works',
    ragHowItWorksText: 'Documents are split into chunks, converted into vectors (embeddings) or indexed by keywords, then the most relevant chunks are injected into the LLM prompt.',
    ragEmbedding: 'Embedding LLM',
    ragEmbeddingText: 'Best accuracy requires an embedding model (e.g. nomic-embed-text, mxbai-embed-large). If you only have a chat LLM, enable keyword fallback to use plain text search instead.',
    ragKnowledgeGraph: 'Knowledge graph',
    ragKnowledgeGraphText: 'Grows automatically as you chat. Sessions and topics become nodes; related sessions become edges.',
    ragDataLocation: 'Where to put data',
    ragDataLocationText: 'Drop files into the RAG folder for the active database. Each database is a separate collection.',
    ragMultipleDbs: 'Multiple databases',
    ragMultipleDbsText: 'Create separate databases for different projects. Switch between them in the settings below.',
    ragNoWebSearch: 'RAG is local document search. It is separate from web search or online LLMs.',
    chunking: 'Chunking',
    semanticSearch: 'Semantic search',
    embeddingModel: 'Embedding model',
    embeddingProvider: 'Embedding provider',
    embeddingApiKey: 'Embedding API key',
    embeddingApiBase: 'API base URL',
    noEmbeddingModel: 'Use keyword search instead of embeddings',
    agent: 'Agent',
    toolsSection: 'Tools',
    systemSection: 'System',
    chat: 'Chat',
    analytics: 'Analytics',
    presets: 'Presets',
    knowledgeGraph: 'Knowledge Graph',
    customTools: 'Custom Tools',
    scheduledTasks: 'Scheduled Tasks',
    statusSection: 'Status',
    settingsSection: 'Settings',
    personaSubtitle: 'Choose a persona to change how {{name}} responds.',
    memorySubtitle: 'Save facts and preferences so {{name}} remembers them.',
    tasksSubtitle: 'Schedule prompts to run automatically.',
    toolsSubtitle: 'Register custom HTTP tools {{name}} can call.',
    statusSubtitle: 'System health and active configuration.',
    settingsSubtitle: 'Customize language, model, and UI behavior.',
    presetSubtitle: 'Quick agent presets.',
    graphSubtitle: 'Visual map of sessions and topics.',
    add: 'Add',
    type: 'Type',
    key: 'Key',
    value: 'Value',
    fact: 'Fact',
    preference: 'Preference',
    prompt: 'Prompt',
    description: 'Description',
    command: 'Command',
    url: 'URL',
    test: 'Test',
    search: 'Search',
    createTask: 'Create Task',
    run: 'Run',
    daily: 'Daily',
    hourly: 'Hourly',
    weekly: 'Weekly',
    custom: 'Custom cron',
    cronExpression: 'Cron expression',
    promptToRun: 'Prompt to run',
    mcpServers: 'MCP Servers',
    addMcpServer: 'Add MCP Server',
    active: 'Active',
    inactive: 'Inactive',
    connected: 'Connected',
    disconnected: 'Disconnected',
    online: 'Online',
    offlineStatus: 'Offline',
    aiSetup: 'AI Setup',
    connecting: 'Connecting',
    chooseLanguage: 'Choose your language',
    chooseAiName: 'Choose a name for your AI',
    start: 'Start',
    memoriesLabel: 'Memories',
    ragDatabases: 'Databases',
    ragUpload: 'Upload documents',
    ragUploadBtn: 'Choose files',
    ragScanBtn: '📁 Scan folder',
    ragEnable: 'Enable RAG',
    ragChunkOverlap: 'Chunk overlap',
    ragRetrievalTemp: 'Retrieval temperature',
    saveRag: 'Save RAG Settings',
    approvalQueue: 'Approval Queue',
    approvalQueuePending: 'Memory approval queue pending',
    goToMemory: 'Go to Memory',
    searchMemories: 'Search memories...',
    backup: 'Backup',
    restore: 'Restore',
    addMemory: 'Add Memory',
    factsLabel: 'Facts',
    preferencesLabel: 'Preferences',
    taskHistory: 'Task History',
    welcomeSubtitle: 'Your local, secure AI agent. Select a persona and start chatting, or try one of the suggestions below.',
  },
  pt: {
    newChat: 'Novo chat',
    send: 'Enviar',
    messagePlaceholder: 'Mensagem para {{name}}...',
    searchChats: 'Buscar chats',
    history: 'Histórico',
    status: 'Status',
    agents: 'Agentes',
    tools: 'Ferramentas',
    memory: 'Memória',
    system: 'Sistema',
    graph: 'Grafo',
    settings: 'Configurações',
    tasks: 'Tarefas Agendadas',
    research: 'Pesquisar Chats',
    welcome: 'Bem-vindo ao {{name}}',
    offline: 'Você está offline — as mensagens serão enfileiradas',
    thinking: 'Pensando...',
    noChats: 'Nenhum chat ainda',
    noMemories: 'Nenhuma memória ainda',
    noTasks: 'Nenhuma tarefa agendada ainda.',
    noTools: 'Nenhuma ferramenta personalizada ainda.',
    language: 'Idioma',
    aiName: 'Nome da IA',
    model: 'Modelo',
    temperature: 'Temperatura',
    maxTokens: 'Máx. tokens',
    save: 'Salvar',
    cancel: 'Cancelar',
    remove: 'Remover',
    newDatabaseName: 'Nome do novo banco',
    delete: 'Excluir',
    edit: 'Editar',
    copy: 'Copiar',
    regenerate: 'Regenerar',
    share: 'Compartilhar',
    encryptShare: 'Compartilhamento Criptografado',
    close: 'Fechar',
    listening: 'Ouvindo...',
    toastSessionExpired: 'Sessão expirada. Faça login novamente.',
    toastNoSessionToShare: 'Nenhuma sessão ativa para compartilhar. Envie uma mensagem primeiro.',
    toastShareCopied: 'Link da sessão copiado',
    toastShareFailed: 'Falha ao compartilhar: {{error}}',
    toastTaskScheduled: 'Tarefa agendada',
    toastTaskDeleted: 'Tarefa excluída',
    toastToolCreated: 'Ferramenta criada',
    toastToolDeleted: 'Ferramenta excluída',
    toastMemorySaved: 'Memória salva',
    toastSettingsSaved: 'Configurações salvas',
    toastFailed: 'Falha: {{error}}',
    rag: 'Sistema RAG',
    ragDescription: 'Geração Aumentada por Recuperação permite que {{name}} busque seus documentos antes de responder.',
    ragHowItWorks: 'Como funciona',
    ragHowItWorksText: 'Documentos são divididos em fragmentos, convertidos em vetores (embeddings) ou indexados por palavras-chave, e os fragmentos mais relevantes são injetados no prompt do LLM.',
    ragEmbedding: 'LLM de embeddings',
    ragEmbeddingText: 'A melhor precisão exige um modelo de embeddings (ex: nomic-embed-text, mxbai-embed-large). Se você só tem um LLM de chat, habilite a busca por palavras-chave.',
    ragKnowledgeGraph: 'Grafo de conhecimento',
    ragKnowledgeGraphText: 'Cresce automaticamente conforme você conversa. Sessões e tópicos viram nós; sessões relacionadas viram arestas.',
    ragDataLocation: 'Onde colocar os dados',
    ragDataLocationText: 'Coloque arquivos na pasta RAG do banco de dados ativo. Cada banco é uma coleção separada.',
    ragMultipleDbs: 'Múltiplos bancos',
    ragMultipleDbsText: 'Crie bancos separados para projetos diferentes. Troque entre eles nas configurações abaixo.',
    ragNoWebSearch: 'RAG é busca local em documentos. É separado de busca na web ou LLMs online.',
    chunking: 'Fragmentação',
    semanticSearch: 'Busca semântica',
    embeddingModel: 'Modelo de embeddings',
    embeddingProvider: 'Provedor de embeddings',
    embeddingApiKey: 'Chave de API de embeddings',
    embeddingApiBase: 'URL base da API',
    noEmbeddingModel: 'Usar busca por palavras-chave em vez de embeddings',
    agent: 'Agente',
    toolsSection: 'Ferramentas',
    systemSection: 'Sistema',
    chat: 'Chat',
    analytics: 'Análises',
    presets: 'Predefinições',
    knowledgeGraph: 'Grafo de Conhecimento',
    customTools: 'Ferramentas Personalizadas',
    scheduledTasks: 'Tarefas Agendadas',
    statusSection: 'Status',
    settingsSection: 'Configurações',
    personaSubtitle: 'Escolha uma persona para mudar como {{name}} responde.',
    memorySubtitle: 'Salve fatos e preferências para {{name}} lembrar.',
    tasksSubtitle: 'Agende prompts para rodar automaticamente.',
    toolsSubtitle: 'Registre ferramentas HTTP que {{name}} pode chamar.',
    statusSubtitle: 'Saúde do sistema e configuração ativa.',
    settingsSubtitle: 'Personalize idioma, modelo e comportamento da interface.',
    presetSubtitle: 'Predefinições rápidas de agente.',
    graphSubtitle: 'Mapa visual de sessões e tópicos.',
    add: 'Adicionar',
    type: 'Tipo',
    key: 'Chave',
    value: 'Valor',
    fact: 'Fato',
    preference: 'Preferência',
    prompt: 'Prompt',
    description: 'Descrição',
    command: 'Comando',
    url: 'URL',
    test: 'Testar',
    search: 'Buscar',
    createTask: 'Criar Tarefa',
    run: 'Rodar',
    daily: 'Diário',
    hourly: 'Por hora',
    weekly: 'Semanal',
    custom: 'Cron personalizado',
    cronExpression: 'Expressão cron',
    promptToRun: 'Prompt a executar',
    mcpServers: 'Servidores MCP',
    addMcpServer: 'Adicionar Servidor MCP',
    active: 'Ativo',
    inactive: 'Inativo',
    connected: 'Conectado',
    disconnected: 'Desconectado',
    online: 'Online',
    offlineStatus: 'Offline',
    aiSetup: 'Configuração de IA',
    connecting: 'Conectando',
    chooseLanguage: 'Escolha seu idioma',
    chooseAiName: 'Escolha um nome para sua IA',
    start: 'Iniciar',
    memoriesLabel: 'Memórias',
    ragDatabases: 'Bancos de dados',
    ragUpload: 'Enviar documentos',
    ragUploadBtn: 'Escolher arquivos',
    ragScanBtn: '📁 Escanear pasta',
    ragEnable: 'Ativar RAG',
    ragChunkOverlap: 'Sobreposição',
    ragRetrievalTemp: 'Temperatura de recuperação',
    saveRag: 'Salvar Configurações RAG',
    approvalQueue: 'Fila de Aprovação',
    approvalQueuePending: 'Fila de aprovação de memória pendente',
    goToMemory: 'Ir para Memória',
    searchMemories: 'Buscar memórias...',
    backup: 'Backup',
    restore: 'Restaurar',
    addMemory: 'Adicionar Memória',
    factsLabel: 'Fatos',
    preferencesLabel: 'Preferências',
    taskHistory: 'Histórico de Tarefas',
    welcomeSubtitle: 'Seu agente de IA local e seguro. Escolha uma persona e comece a conversar, ou experimente uma das sugestões abaixo.',
  },
  zh: {
    newChat: '新对话',
    send: '发送',
    messagePlaceholder: '给 {{name}} 发消息...',
    searchChats: '搜索对话',
    history: '历史',
    status: '状态',
    agents: '模型',
    tools: '工具',
    memory: '记忆',
    system: '系统',
    graph: '图谱',
    settings: '设置',
    tasks: '定时任务',
    research: '搜索对话',
    welcome: '欢迎使用 {{name}}',
    offline: '你已离线 — 消息将被排队',
    thinking: '思考中...',
    noChats: '暂无对话',
    noMemories: '暂无记忆',
    noTasks: '暂无定时任务。',
    noTools: '暂无自定义工具。',
    language: '语言',
    aiName: 'AI 名称',
    model: '模型',
    temperature: '温度',
    maxTokens: '最大 tokens',
    save: '保存',
    cancel: '取消',
    remove: '移除',
    newDatabaseName: '新数据库名称',
    delete: '删除',
    edit: '编辑',
    copy: '复制',
    regenerate: '重新生成',
    share: '分享',
    encryptShare: '加密分享',
    close: '关闭',
    listening: '聆听中...',
    toastSessionExpired: '会话已过期，请重新登录。',
    toastNoSessionToShare: '没有可分享的活跃会话。请先发送消息。',
    toastShareCopied: '会话链接已复制',
    toastShareFailed: '分享失败：{{error}}',
    toastTaskScheduled: '任务已创建',
    toastTaskDeleted: '任务已删除',
    toastToolCreated: '工具已创建',
    toastToolDeleted: '工具已删除',
    toastMemorySaved: '记忆已保存',
    toastSettingsSaved: '设置已保存',
    toastFailed: '失败：{{error}}',
    rag: 'RAG 系统',
    ragDescription: '检索增强生成让 {{name}} 在回答前先搜索你的文档。',
    ragHowItWorks: '工作原理',
    ragHowItWorksText: '文档被切分成块，转换为向量（embeddings）或按关键词索引，然后将最相关的块注入到 LLM 提示词中。',
    ragEmbedding: '嵌入模型',
    ragEmbeddingText: '最佳精度需要一个嵌入模型（例如 nomic-embed-text、mxbai-embed-large）。如果你只有聊天 LLM，请启用关键词回退。',
    ragKnowledgeGraph: '知识图谱',
    ragKnowledgeGraphText: '随着你聊天自动增长。会话和主题成为节点；相关会话成为边。',
    ragDataLocation: '数据放在哪里',
    ragDataLocationText: '将文件放入活动数据库的 RAG 文件夹中。每个数据库是一个独立的集合。',
    ragMultipleDbs: '多个数据库',
    ragMultipleDbsText: '为不同项目创建独立数据库。在下方设置中切换。',
    ragNoWebSearch: 'RAG 是本地文档搜索，与网络搜索或在线 LLM 是分开的。',
    chunking: '分块',
    semanticSearch: '语义搜索',
    embeddingModel: '嵌入模型',
    embeddingProvider: '嵌入提供商',
    embeddingApiKey: '嵌入 API 密钥',
    embeddingApiBase: 'API 基础 URL',
    noEmbeddingModel: '不使用嵌入模型，改用关键词搜索',
    agent: '代理',
    toolsSection: '工具',
    systemSection: '系统',
    chat: '聊天',
    analytics: '分析',
    presets: '预设',
    knowledgeGraph: '知识图谱',
    customTools: '自定义工具',
    scheduledTasks: '定时任务',
    statusSection: '状态',
    settingsSection: '设置',
    personaSubtitle: '选择一个人格来改变 {{name}} 的回复方式。',
    memorySubtitle: '保存事实和偏好，让 {{name}} 记住。',
    tasksSubtitle: '安排提示词自动运行。',
    toolsSubtitle: '注册 {{name}} 可以调用的 HTTP 工具。',
    statusSubtitle: '系统健康和活动配置。',
    settingsSubtitle: '自定义语言、模型和界面行为。',
    presetSubtitle: '快速代理预设。',
    graphSubtitle: '会话和主题的可视化地图。',
    add: '添加',
    type: '类型',
    key: '键',
    value: '值',
    fact: '事实',
    preference: '偏好',
    prompt: '提示词',
    description: '描述',
    command: '命令',
    url: 'URL',
    test: '测试',
    search: '搜索',
    createTask: '创建任务',
    run: '运行',
    daily: '每天',
    hourly: '每小时',
    weekly: '每周',
    custom: '自定义 cron',
    cronExpression: 'Cron 表达式',
    promptToRun: '要运行的提示词',
    mcpServers: 'MCP 服务器',
    addMcpServer: '添加 MCP 服务器',
    active: '活跃',
    inactive: '非活跃',
    connected: '已连接',
    disconnected: '未连接',
    online: '在线',
    offlineStatus: '离线',
    aiSetup: 'AI 设置',
    connecting: '连接中',
    chooseLanguage: '选择你的语言',
    chooseAiName: '为你的 AI 选择一个名称',
    start: '开始',
    memoriesLabel: '记忆',
    ragDatabases: '数据库',
    ragUpload: '上传文档',
    ragUploadBtn: '选择文件',
    ragScanBtn: '📁 扫描文件夹',
    ragEnable: '启用 RAG',
    ragChunkOverlap: '块重叠',
    ragRetrievalTemp: '检索温度',
    saveRag: '保存 RAG 设置',
    approvalQueue: '审批队列',
    approvalQueuePending: '记忆审批队列待处理',
    goToMemory: '前往记忆',
    searchMemories: '搜索记忆...',
    backup: '备份',
    restore: '恢复',
    addMemory: '添加记忆',
    factsLabel: '事实',
    preferencesLabel: '偏好',
    taskHistory: '任务历史',
    welcomeSubtitle: '你的本地安全 AI 助手。选择人格并开始聊天，或尝试下面的建议。',
  }
};

const SUGGESTIONS = {
  en: [
    { label: 'Summarize my notes', prompt: 'Can you summarize the key points from my notes?' },
    { label: 'Draft an email', prompt: 'Help me draft a professional email.' },
    { label: 'Explain a concept', prompt: 'Explain quantum computing in simple terms.' },
    { label: 'Debug my code', prompt: 'Help me debug this code.\n\n[paste your code here]' },
    { label: 'Plan my day', prompt: 'Can you help me plan my day?' },
    { label: 'Write a blog post', prompt: 'Write a short blog post about AI privacy.' },
    { label: 'Compare options', prompt: 'Compare Rust vs Go for a backend service.' },
    { label: 'Brainstorm ideas', prompt: 'Brainstorm marketing ideas for a coffee shop.' },
  ],
  pt: [
    { label: 'Resumir minhas notas', prompt: 'Você pode resumir os pontos principais das minhas notas?' },
    { label: 'Escrever um email', prompt: 'Me ajude a escrever um email profissional.' },
    { label: 'Explicar um conceito', prompt: 'Explique computação quântica de forma simples.' },
    { label: 'Depurar meu código', prompt: 'Me ajude a depurar este código.\n\n[cole seu código aqui]' },
    { label: 'Planejar meu dia', prompt: 'Você pode me ajudar a planejar meu dia?' },
    { label: 'Escrever um post', prompt: 'Escreva um post curto sobre privacidade em IA.' },
    { label: 'Comparar opções', prompt: 'Compare Rust vs Go para um serviço backend.' },
    { label: 'Brainstorm de ideias', prompt: 'Sugira ideias de marketing para uma cafeteria.' },
  ],
  zh: [
    { label: '总结我的笔记', prompt: '你能总结我笔记的要点吗？' },
    { label: '起草一封邮件', prompt: '帮我起草一封专业的邮件。' },
    { label: '解释一个概念', prompt: '用简单的语言解释量子计算。' },
    { label: '调试我的代码', prompt: '帮我调试这段代码。\n\n[在此粘贴你的代码]' },
    { label: '规划我的一天', prompt: '你能帮我规划今天吗？' },
    { label: '写一篇博客', prompt: '写一篇关于 AI 隐私的短文。' },
    { label: '比较选项', prompt: '比较 Rust 和 Go 用于后端服务。' },
    { label: '头脑风暴', prompt: '为一家咖啡店头脑风暴营销创意。' },
  ]
};

function t(key, vars = {}) {
  const lang = localStorage.getItem('language') || document.documentElement.getAttribute('lang') || 'en';
  let text = TRANSLATIONS[lang]?.[key] ?? TRANSLATIONS.en[key] ?? key;
  Object.entries(vars).forEach(([k, v]) => {
    text = text.replace(new RegExp('{{' + k + '}}', 'g'), v);
  });
  return text;
}

function applyTranslations() {
  const lang = localStorage.getItem('language') || document.documentElement.getAttribute('lang') || 'en';
  document.documentElement.setAttribute('lang', lang);
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.dataset.i18n;
    const vars = { name: aiName };
    if (el.dataset.i18nHtml === 'true') {
      el.innerHTML = t(key, vars);
    } else {
      el.textContent = t(key, vars);
    }
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const key = el.dataset.i18nPlaceholder;
    el.placeholder = t(key, { name: aiName });
  });
  const input = document.getElementById('input');
  if (input) input.placeholder = t('messagePlaceholder', { name: aiName });
  const welcome = document.querySelector('.welcome-message h2');
  if (welcome) welcome.textContent = '🐄 ' + t('welcome', { name: aiName });
  const messagesEl = document.getElementById('messages');
  if (messagesEl && messagesEl.querySelector('.welcome-message') && messagesEl.children.length === 1) {
    showWelcome();
  }
  // Update dynamic page title and connection status label
  const activeTab = document.querySelector('.tab.active');
  if (activeTab) {
    const tabId = activeTab.id.replace('tab-', '');
    const tabTitles = {
      chat: 'chat', memory: 'memory', personas: 'personas', rag: 'rag',
      analytics: 'analytics', presets: 'presets', graph: 'knowledgeGraph',
      tools: 'customTools', tasks: 'scheduledTasks', status: 'statusSection',
      settings: 'settingsSection', mcp: 'mcpServers'
    };
    const pageTitle = document.getElementById('pageTitle');
    if (pageTitle) {
      const key = tabTitles[tabId] || tabId;
      pageTitle.dataset.i18n = key;
      pageTitle.textContent = t(key);
    }
  }
  const statusLabel = document.querySelector('#connectionStatus .status-label');
  if (statusLabel) {
    const key = document.getElementById('connectionStatus')?.classList.contains('online') ? 'online' : 'offlineStatus';
    statusLabel.dataset.i18n = key;
    statusLabel.textContent = t(key);
  }
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
}

function getWelcomeHTML() {
  const lang = localStorage.getItem('language') || document.documentElement.getAttribute('lang') || 'en';
  const pool = SUGGESTIONS[lang] || SUGGESTIONS.en;
  const shuffled = [...pool].sort(() => Math.random() - 0.5);
  const picks = shuffled.slice(0, 4);
  const chips = picks.map(s =>
    `<button class="prompt-chip" data-prompt="${escapeHtml(s.prompt)}">${escapeHtml(s.label)}</button>`
  ).join('');
  return `
    <div class="welcome-message">
      <h2>🐄 ${t('welcome', { name: aiName })}</h2>
      <p>${t('welcomeSubtitle', { name: aiName })}</p>
      <div class="prompt-suggestions">
        ${chips}
      </div>
    </div>
  `;
}

function showWelcome() {
  const messages = document.getElementById('messages');
  if (!messages) return;
  messages.innerHTML = getWelcomeHTML();
  messages.querySelectorAll('.prompt-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const input = document.getElementById('input');
      if (input) {
        input.value = chip.dataset.prompt;
        input.focus();
      }
    });
  });
}

// ===== Sound Notifications =====
let soundEnabled = localStorage.getItem('soundEnabled') !== 'false'; // default on

function playNotificationSound() {
  if (!soundEnabled) return;
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.type = 'sine';
    osc.frequency.setValueAtTime(523.25, ctx.currentTime); // C5
    osc.frequency.exponentialRampToValueAtTime(659.25, ctx.currentTime + 0.08); // E5
    gain.gain.setValueAtTime(0.08, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.25);
    osc.start(ctx.currentTime);
    osc.stop(ctx.currentTime + 0.25);
  } catch (e) {
    // AudioContext may be blocked until user interaction
  }
}

function setSoundEnabled(enabled) {
  soundEnabled = enabled;
  localStorage.setItem('soundEnabled', String(enabled));
}

// ===== Chat Persistence =====
function saveChat() {
  const messages = Array.from(document.querySelectorAll('.message')).map(m => ({
    text: m.dataset.rawText || '',
    isUser: m.classList.contains('user'),
    time: m.querySelector('.msg-time')?.textContent || ''
  }));
  localStorage.setItem('chat_messages', JSON.stringify(messages));
}

function loadChat() {
  const raw = localStorage.getItem('chat_messages');
  if (!raw) return;
  try {
    const messages = JSON.parse(raw);
    const container = document.getElementById('messages');
    if (!container) return;
    container.innerHTML = '';
    messages.forEach(m => {
      if (m.text) addMessage(m.text, m.isUser);
    });
  } catch (e) {
    console.error('Failed to load chat', e);
  }
}

function clearChatStorage() {
  localStorage.removeItem('chat_messages');
}

// ===== Theme System =====
function applyTheme(name) {
  currentTheme = name;
  localStorage.setItem('theme', name);
  let link = document.getElementById('theme-link');
  if (!link) {
    link = document.createElement('link');
    link.id = 'theme-link';
    link.rel = 'stylesheet';
    document.head.appendChild(link);
  }
  // Smooth transition: add a class that dims the body, swap, then restore
  document.body.classList.add('theme-transitioning');
  link.href = `/themes/${name}-v4.css?v=${THEME_CSS_VERSION}`;
  document.body.setAttribute('data-theme', name);
  setTimeout(() => document.body.classList.remove('theme-transitioning'), 350);
}

function showThemePicker() {
  const modal = document.getElementById('themePickerModal');
  if (modal) modal.style.display = 'flex';
}

function initTheme() {
  const saved = localStorage.getItem('theme');
  if (!saved) {
    // Default to dark-chat so first load is usable without forcing a choice.
    localStorage.setItem('theme', 'dark-chat');
    applyTheme('dark-chat');
  } else {
    applyTheme(saved);
  }
}

// ===== Auth (disabled — no login required) =====
// The web UI runs without authentication. All auth endpoints are bypassed.

async function fetchCsrf() {
  try {
    const res = await fetch(`${API}/api/csrf`);
    if (res.ok) {
      const data = await res.json();
      csrfToken = data.csrf_token || '';
      localStorage.setItem('csrf_token', csrfToken);
    }
  } catch (_) {}
}

function logout() {
  token = '';
  localStorage.removeItem('token');
  localStorage.removeItem('aiName');
  location.reload();
}

function maybeShowNameAiModal() {
  if (!localStorage.getItem('aiName') || !localStorage.getItem('language')) {
    setTimeout(() => openModal('nameAiModal'), 400);
  }
}

// ===== Tabs =====
async function switchTab(tabId) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const tab = document.getElementById('tab-' + tabId);
  if (tab) tab.classList.add('active');
  const nav = document.querySelector(`.nav-item[data-tab="${tabId}"]`);
  if (nav) nav.classList.add('active');
  const tabTitles = {
    chat: 'chat',
    memory: 'memory',
    personas: 'personas',
    rag: 'rag',
    analytics: 'analytics',
    presets: 'presets',
    graph: 'knowledgeGraph',
    tools: 'customTools',
    tasks: 'scheduledTasks',
    status: 'statusSection',
    settings: 'settingsSection',
    mcp: 'mcpServers'
  };
  const pageTitle = document.getElementById('pageTitle');
  if (pageTitle) {
    const key = tabTitles[tabId] || tabId;
    pageTitle.dataset.i18n = key;
    pageTitle.textContent = t(key);
  }
  if (tabId === 'graph') await renderGraph();
}

// ===== Chat =====
let currentStreamEl = null;
let streamInterval = null;

function shouldAutoScroll(container) {
  if (!autoScrollEnabled) return false;
  const threshold = 100; // pixels from bottom
  return container.scrollHeight - container.scrollTop - container.clientHeight < threshold;
}

function updateScrollButton() {
  const container = document.getElementById('messages');
  const btn = document.getElementById('scrollBottomBtn');
  if (!container || !btn) return;
  const nearBottom = shouldAutoScroll(container);
  btn.classList.toggle('visible', !nearBottom);
  if (nearBottom) {
    unreadMessages = 0;
    btn.textContent = '⬇';
  } else if (unreadMessages > 0) {
    btn.textContent = '⬇ ' + unreadMessages;
  }
}

function timeAgo(date) {
  const now = new Date();
  const diff = Math.floor((now - date) / 1000);
  if (diff < 60) return 'just now';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  return Math.floor(diff / 86400) + 'd ago';
}

function stripMemoryTags(text) {
  return String(text).replace(/<memory\b[^>]*>[\s\S]*?<\/memory>/gi, '').trim();
}

function smartSpacing(text) {
  // Fix models that occasionally generate text without spaces
  let s = text;
  // Space after sentence-ending punctuation followed by capital letter
  s = s.replace(/([.!?])([A-Z])/g, '$1 $2');
  // Space between lowercase letter and uppercase letter (camelCase separation)
  s = s.replace(/([a-z])([A-Z])/g, '$1 $2');
  // Space after comma if missing
  s = s.replace(/([a-zA-Z]),([a-zA-Z])/g, '$1, $2');
  return s;
}

function addMessage(text, isUser) {
  const container = document.getElementById('messages');
  const welcome = container.querySelector('.welcome-message');
  if (welcome) welcome.remove();

  text = stripMemoryTags(text);
  const div = document.createElement('div');
  div.className = 'message ' + (isUser ? 'user' : 'ai');
  div.dataset.rawText = text;
  const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  const reactions = !isUser
    ? `<div class="msg-reactions">
        <button class="msg-reaction-btn" data-reaction="up" title="Helpful">👍</button>
        <button class="msg-reaction-btn" data-reaction="down" title="Not helpful">👎</button>
       </div>`
    : '';

  const actions = isUser
    ? `<div class="msg-actions">
        <button class="msg-action-btn" data-action="edit" title="Edit">✏️</button>
        <button class="msg-action-btn" data-action="copy" title="Copy">📋</button>
        <button class="msg-action-btn" data-action="delete" title="Delete">🗑️</button>
       </div>`
    : `<div class="msg-actions">
        <button class="msg-action-btn" data-action="copy" title="Copy">📋</button>
        <button class="msg-action-btn" data-action="regenerate" title="Regenerate">🔄</button>
        <button class="msg-action-btn" data-action="delete" title="Delete">🗑️</button>
       </div>`;

  const now = new Date();
  const timeAgoStr = timeAgo(now);
  div.innerHTML = '<span class="msg-time" title="' + timeAgoStr + '">' + time + '</span><div class="msg-body">' + formatMarkdown(text) + '</div>' + actions;
  container.appendChild(div);
  highlightCodeBlocks(div);
  if (shouldAutoScroll(container)) {
    container.scrollTop = container.scrollHeight;
  }
  saveChat();
  // Update tab title and favicon when new message arrives
  if (!isUser) {
    playNotificationSound();
    const container = document.getElementById('messages');
    if (container && !shouldAutoScroll(container)) {
      unreadMessages++;
      updateScrollButton();
    }
    if (document.hidden) {
      document.title = '💬 New message · ' + aiName;
      unreadCount++;
      updateFaviconBadge(unreadCount);
    }
  }
  return div;
}

let codeBlockId = 0;
const codeBlockMap = new Map();
let unreadCount = 0;
const originalFavicon = document.querySelector('link[rel="icon"]')?.href || '';

function updateFaviconBadge(count) {
  const canvas = document.createElement('canvas');
  canvas.width = 64;
  canvas.height = 64;
  const ctx = canvas.getContext('2d');
  // Draw simple cow emoji background
  ctx.fillStyle = '#0d0d0d';
  ctx.fillRect(0, 0, 64, 64);
  ctx.font = '48px serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText('🐄', 32, 32);
  if (count > 0) {
    ctx.fillStyle = '#ff6b6b';
    ctx.beginPath();
    ctx.arc(52, 12, 10, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = '#fff';
    ctx.font = 'bold 12px sans-serif';
    ctx.fillText(count > 9 ? '9+' : String(count), 52, 12);
  }
  const link = document.querySelector('link[rel="icon"]');
  if (link) link.href = canvas.toDataURL();
}

function formatMarkdown(text) {
  // Process code blocks first so inline rules don't touch them
  const codeBlocks = [];
  text = text.replace(/```(\w*)\n?([\s\S]*?)```/g, (match, lang, code) => {
    const placeholder = '\x00CODEBLOCK' + codeBlocks.length + '\x00';
    const id = 'cb-' + (++codeBlockId);
    codeBlockMap.set(id, code.trim());
    const label = lang ? `<span class="code-lang-label">${escapeHtml(lang)}</span>` : '';
    codeBlocks.push(`<div style="position:relative;margin:8px 0;">
      ${label}
      <button class="btn btn-secondary copy-code-btn" data-id="${id}" style="position:absolute;top:6px;right:6px;padding:4px 10px;font-size:0.75rem;opacity:0;transition:opacity 0.2s;">Copy</button>
      <pre style="background:rgba(0,0,0,0.2);padding:12px;border-radius:8px;overflow-x:auto;font-family:monospace;font-size:0.85em;margin:0;"><code${lang ? ` class="language-${escapeHtml(lang)}"` : ''}>${escapeHtml(code.trim())}</code></pre>
    </div>`);
    return placeholder;
  });

  // Apply smart spacing only to non-code text
  text = smartSpacing(text);

  // Escape remaining HTML
  let html = escapeHtml(text);

  // Inline formatting
  html = html
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/`([^`]+)`/g, '<code style="background:rgba(255,255,255,0.1);padding:2px 4px;border-radius:4px;font-family:monospace;font-size:0.85em;">$1</code>');

  // Block-level formatting (process line by line)
  const lines = html.split('\n');
  const out = [];
  let inList = false;
  let listType = null;

  function closeList() {
    if (!inList) return;
    out.push(listType === 'ol' ? '</ol>' : '</ul>');
    inList = false;
    listType = null;
  }

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];

    // Code block placeholders pass through untouched
    if (line.includes('\x00CODEBLOCK')) {
      closeList();
      out.push(line);
      continue;
    }

    // Headers
    if (line.startsWith('### ')) { closeList(); out.push('<h3 style="font-size:1.05rem;font-weight:600;margin:12px 0 6px;">' + line.slice(4) + '</h3>'); continue; }
    if (line.startsWith('## ')) { closeList(); out.push('<h2 style="font-size:1.15rem;font-weight:600;margin:14px 0 8px;">' + line.slice(3) + '</h2>'); continue; }
    if (line.startsWith('# ')) { closeList(); out.push('<h1 style="font-size:1.3rem;font-weight:700;margin:16px 0 10px;">' + line.slice(2) + '</h1>'); continue; }

    // Horizontal rule
    if (/^---+\s*$/.test(line)) { closeList(); out.push('<hr style="border:none;border-top:1px solid var(--border);margin:12px 0;opacity:0.4;">'); continue; }

    // Blockquote
    if (line.startsWith('> ')) { closeList(); out.push('<blockquote style="border-left:3px solid var(--accent);padding-left:10px;margin:8px 0;color:var(--text-dim);font-style:italic;">' + line.slice(2) + '</blockquote>'); continue; }

    // Unordered list
    const ulMatch = line.match(/^(\s*)[-\*]\s+(.*)$/);
    if (ulMatch) {
      if (!inList || listType !== 'ul') { closeList(); out.push('<ul style="margin:6px 0 6px 18px;">'); inList = true; listType = 'ul'; }
      out.push('<li>' + ulMatch[2] + '</li>');
      continue;
    }

    // Ordered list
    const olMatch = line.match(/^(\s*)\d+\.\s+(.*)$/);
    if (olMatch) {
      if (!inList || listType !== 'ol') { closeList(); out.push('<ol style="margin:6px 0 6px 18px;">'); inList = true; listType = 'ol'; }
      out.push('<li>' + olMatch[2] + '</li>');
      continue;
    }

    // Empty line
    if (line.trim() === '') {
      closeList();
      out.push('<br>');
      continue;
    }

    // Regular paragraph
    closeList();
    out.push('<p style="margin:4px 0;">' + line + '</p>');
  }
  closeList();

  html = out.join('\n');

  // Restore code blocks
  codeBlocks.forEach((block, i) => {
    html = html.replace('\x00CODEBLOCK' + i + '\x00', block);
  });

  // Links (must be after HTML escape, but we need to be careful)
  html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer" style="color:var(--accent);text-decoration:underline;">$1</a>');

  return html;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function highlightCodeBlocks(root) {
  if (typeof hljs === 'undefined') return;
  root.querySelectorAll('pre code').forEach(block => {
    if (!block.classList.contains('hljs')) {
      hljs.highlightElement(block);
    }
  });
}

function startStreamProgressWords() {
  const progress = document.getElementById('streamProgress');
  if (progress) progress.classList.add('hidden');
}

function stopStreamProgressWords() {
  const progress = document.getElementById('streamProgress');
  if (progress) progress.classList.add('hidden');
}

// Global thinking panel (Claude/Kimi style) above the input
let thinkingPanelInterval = null;
function showThinkingPanel() {
  const panel = document.getElementById('thinkingPanel');
  const word = document.getElementById('thinkingPanelWord');
  const content = document.getElementById('thinkingPanelContent');
  if (!panel) return;
  panel.classList.remove('hidden');
  if (content) content.textContent = '';
  let i = Math.floor(Math.random() * THINKING_WORDS.length);
  if (word) word.textContent = THINKING_WORDS[i] + '...';
  if (thinkingPanelInterval) clearInterval(thinkingPanelInterval);
  thinkingPanelInterval = setInterval(() => {
    i = (i + 1) % THINKING_WORDS.length;
    if (word) word.textContent = THINKING_WORDS[i] + '...';
  }, 1800);
}
function hideThinkingPanel() {
  const panel = document.getElementById('thinkingPanel');
  if (thinkingPanelInterval) clearInterval(thinkingPanelInterval);
  thinkingPanelInterval = null;
  if (panel) {
    panel.classList.add('hidden');
    panel.classList.remove('expanded');
  }
}
function appendThinkingPanel(text) {
  const content = document.getElementById('thinkingPanelContent');
  if (!content) return;
  content.textContent = (content.textContent || '') + text;
  content.scrollTop = content.scrollHeight;
}

function startStream() {
  currentThinkingWordIndex = 0;
  stopStreamProgressWords();
  showThinkingPanel();
  const container = document.getElementById('messages');
  const welcome = container.querySelector('.welcome-message');
  if (welcome) welcome.remove();

  if (currentStreamEl) currentStreamEl.remove();
  if (streamInterval) clearInterval(streamInterval);

  const stopBtn = document.getElementById('stopBtn');
  if (stopBtn) stopBtn.classList.remove('hidden');

  const div = document.createElement('div');
  div.className = 'message ai';
  const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  div.innerHTML = '<span class="msg-time">' + time + '</span>' +
    '<div class="msg-body"><span class="stream-cursor">▋</span></div>';
  container.appendChild(div);
  currentStreamEl = div;
  container.scrollTop = container.scrollHeight;
  return div;
}

function appendStream(text) {
  if (!currentStreamEl) return;
  text = stripMemoryTags(text);
  const body = currentStreamEl.querySelector('.msg-body');
  if (!body) return;
  const cursor = body.querySelector('.stream-cursor');
  if (cursor) cursor.remove();

  // Separate thinking tokens produced by reasoning models (e.g. <think>).
  if (text.startsWith('__THINK__')) {
    const think = text.slice(9);
    appendThinkingPanel(think);
    const panel = document.getElementById('thinkingPanel');
    if (panel && !panel.classList.contains('expanded')) panel.classList.add('expanded');
    return;
  }

  stopStreamProgressWords();
  const raw = (currentStreamEl.dataset.rawText || '') + text;
  currentStreamEl.dataset.rawText = raw;
  body.innerHTML = formatMarkdown(raw) + '<span class="stream-cursor">▋</span>';
  highlightCodeBlocks(body);
  const container = document.getElementById('messages');
  container.scrollTop = container.scrollHeight;
  const progress = document.getElementById('streamProgress');
  if (progress) {
    progress.classList.remove('hidden');
    progress.textContent = raw.length.toLocaleString() + ' chars generated';
  }
}

function endStream() {
  if (!currentStreamEl) return;
  const el = currentStreamEl;
  const body = el.querySelector('.msg-body');
  if (body) {
    const cursor = body.querySelector('.stream-cursor');
    if (cursor) cursor.remove();
  }
  currentStreamEl = null;
  if (streamInterval) { clearInterval(streamInterval); streamInterval = null; }
  stopStreamProgressWords();
  hideThinkingPanel();
  const stopBtn = document.getElementById('stopBtn');
  if (stopBtn) stopBtn.classList.add('hidden');
  saveChat();
  renderChatHistory();
}

function startThinkingWords() {
  const word = document.getElementById('typingWord');
  if (!word) return;
  let i = Math.floor(Math.random() * THINKING_WORDS.length);
  word.textContent = THINKING_WORDS[i];
  if (thinkingWordInterval) clearInterval(thinkingWordInterval);
  thinkingWordInterval = setInterval(() => {
    i = (i + 1) % THINKING_WORDS.length;
    word.textContent = THINKING_WORDS[i];
  }, 1800);
}
function stopThinkingWords() {
  if (thinkingWordInterval) clearInterval(thinkingWordInterval);
  thinkingWordInterval = null;
}
function showTyping(show, label) {
  const el = document.getElementById('typingIndicator');
  const word = document.getElementById('typingWord');
  if (el) el.classList.toggle('hidden', !show);
  if (!show) {
    stopThinkingWords();
    if (word) word.textContent = '';
  } else if (label) {
    stopThinkingWords();
    if (word) word.textContent = label;
  } else {
    startThinkingWords();
  }
}

let chatRetryCount = 0;
let autoScrollEnabled = localStorage.getItem('autoScrollEnabled') !== 'false';
let unreadMessages = 0;
let currentThinkingWordIndex = 0;
let streamProgressInterval = null;
let attachedImage = null;

async function sendChat() {
  const input = document.getElementById('input');
  const text = input.value.trim();
  if (!text && !attachedImage) return;
  input.value = '';
  localStorage.removeItem('chat_draft');
  const meta = document.getElementById('inputMeta');
  if (meta) meta.textContent = '';

  let imageB64 = null;
  if (attachedImage) {
    try { imageB64 = await fileToBase64(attachedImage); } catch (e) { showToast('Image read failed', 'error'); }
  }

  if (attachedImage) {
    const container = document.getElementById('messages');
    const welcome = container.querySelector('.welcome-message');
    if (welcome) welcome.remove();
    const div = document.createElement('div');
    div.className = 'message user';
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const url = URL.createObjectURL(attachedImage);
    div.innerHTML = `<span class="msg-time">${time}</span><div>${escapeHtml(text || '')}</div><img src="${url}" style="max-width:200px;max-height:200px;border-radius:8px;margin-top:6px;">`;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
  } else {
    addMessage(text, true);
  }
  clearAttachedImage();
  showTyping(true);

  try {
    const headers = {
      'Content-Type': 'application/json',
      // Auth disabled — no Bearer token sent
    };
    if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
    const res = await fetch(`${API}/api/chat`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ message: text || '', session_id: currentSession(), image_b64: imageB64 })
    });
    showTyping(false, aiName + ' is thinking...');
    if (!res.ok) {
      if (res.status === 403) {
        addMessage('Session expired. Please log in again.', false);
        logout();
      } else {
        addMessage('Error: ' + res.status, false);
      }
      return;
    }
    const data = await res.json();
    const response = data.response || data.message || '...';
    // Stream the response character by character for visual effect
    startStream();
    let i = 0;
    const chunkSize = 3;
    const delay = 15;
    streamInterval = setInterval(() => {
      if (i >= response.length) {
        endStream();
        return;
      }
      appendStream(response.slice(i, i + chunkSize));
      i += chunkSize;
    }, delay);
  } catch (e) {
    showTyping(false, aiName + ' is thinking...');
    addMessage('Network error. Retrying in 2s...', false);
    setTimeout(() => {
      document.querySelectorAll('.message').forEach(m => {
        if (m.textContent.includes('Retrying in 2s')) m.remove();
      });
      sendChat();
    }, 2000);
  }
}

// Real SSE streaming chat (used when backend supports it)
async function sendChatStream() {
  const input = document.getElementById('input');
  const text = input.value.trim();
  if (!text && !attachedImage) return;
  input.value = '';
  localStorage.removeItem('chat_draft');

  let imageB64 = null;
  if (attachedImage) {
    try { imageB64 = await fileToBase64(attachedImage); } catch (e) { showToast('Image read failed', 'error'); }
  }

  // Render user message with image preview if attached
  if (attachedImage) {
    const container = document.getElementById('messages');
    const welcome = container.querySelector('.welcome-message');
    if (welcome) welcome.remove();
    const div = document.createElement('div');
    div.className = 'message user';
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const url = URL.createObjectURL(attachedImage);
    div.innerHTML = `<span class="msg-time">${time}</span><div>${escapeHtml(text || '')}</div><img src="${url}" style="max-width:200px;max-height:200px;border-radius:8px;margin-top:6px;">`;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
  } else {
    addMessage(text, true);
  }
  clearAttachedImage();
  showTyping(true);

  try {
    const headers = {
      'Content-Type': 'application/json',
      // Auth disabled — no Bearer token sent
    };
    if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
    const res = await fetch(`${API}/api/chat/stream`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ message: text || '', session_id: currentSession(), image_b64: imageB64 })
    });
    showTyping(false);
    if (!res.ok) {
      if (res.status === 403) {
        addMessage('Session expired. Please log in again.', false);
        logout();
        return;
      }
      // Fall back to non-streaming endpoint
      sendChat();
      return;
    }
    startStream();
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let metaReceived = false;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || !trimmed.startsWith('data: ')) continue;
        const data = trimmed.slice(6);
        if (data === '[DONE]') { endStream(); return; }
        // First data line may be JSON metadata
        if (!metaReceived && data.startsWith('{') && data.endsWith('}')) {
          try {
            const meta = JSON.parse(data);
            if (meta.session_id) localStorage.setItem('session_id', meta.session_id);
            metaReceived = true;
            continue;
          } catch (_) {}
        }
        appendStream(data);
      }
    }
    endStream();
  } catch (e) {
    showTyping(false, aiName + ' is thinking...');
    addMessage('Network error. Retrying in 2s...', false);
    setTimeout(() => {
      document.querySelectorAll('.message').forEach(m => {
        if (m.textContent.includes('Retrying in 2s')) m.remove();
      });
      sendChatStream();
    }, 2000);
  }
}

function currentSession() {
  return localStorage.getItem('session_id') || '';
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result;
      if (typeof result !== 'string') { reject(new Error('Failed to read image')); return; }
      const base64 = result.split(',')[1];
      resolve(base64);
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

async function uploadFile(file) {
  const formData = new FormData();
  formData.append('file', file);
  const headers = {}; // Auth disabled
  if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
  try {
    const res = await fetch(`${API}/api/upload`, {
      method: 'POST',
      headers,
      body: formData
    });
    if (!res.ok) {
      let msg = 'Upload failed: ' + res.status;
      try { const err = await res.json(); if (err.error) msg = err.error; } catch (_) {}
      if (res.status === 403) {
        addMessage('Session expired. Please log in again.', false);
        logout();
        return null;
      }
      throw new Error(msg);
    }
    return await res.json();
  } catch (e) {
    showToast(e.message, 'error');
    return null;
  }
}

// ===== Data Loading =====
async function loadPersonasAndAgents() {
  try {
    const [pRes, aRes] = await Promise.all([
      fetch(`${API}/api/personas`),
      fetch(`${API}/api/agents`)
    ]);
    if (pRes.ok) {
      const data = await pRes.json();
      const sel = document.getElementById('personaSelect');
      if (sel && data.personas) {
        sel.innerHTML = data.personas.map(p => `<option value="${p.name}">${p.emoji || ''} ${p.name}</option>`).join('');
      }
    }
    if (aRes.ok) {
      const data = await aRes.json();
      const sel = document.getElementById('agentSelect');
      if (sel && data.agents) {
        sel.innerHTML = data.agents.map(a => `<option value="${a.name}" data-provider="${a.provider || ''}">${a.name} (${a.model})</option>`).join('');
      }
      updateCloudPrivacyWarning();
    }
  } catch (_) {}
}

function updateCloudPrivacyWarning() {
  const warning = document.getElementById('cloudPrivacyWarning');
  const agentSelect = document.getElementById('agentSelect');
  if (!warning || !agentSelect) return;
  const selectedOption = agentSelect.options[agentSelect.selectedIndex];
  const provider = selectedOption?.dataset?.provider?.toLowerCase() || '';
  warning.style.display = (provider && provider !== 'ollama') ? 'block' : 'none';
}

// ===== Settings =====
function openSettings() { document.getElementById('settingsModal').style.display = 'flex'; }
function closeSettings() { document.getElementById('settingsModal').style.display = 'none'; }

// ===== Modals =====
function openModal(id) { document.getElementById(id).style.display = 'flex'; }
function closeModal(id) { document.getElementById(id).style.display = 'none'; }

// Close modals when clicking outside their content
function initModalOutsideClick() {
  document.addEventListener('click', (e) => {
    const modal = e.target.closest('.modal, .api-key-modal');
    if (!modal || modal.style.display === 'none') return;
    const content = modal.querySelector('.modal-content, .api-key-modal-content, .slide-panel');
    if (content && !content.contains(e.target)) {
      modal.style.display = 'none';
    }
  });
}

// ===== Toast Notifications =====
function showToast(message, type) {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = 'toast ' + (type || 'info');
  toast.textContent = message;
  container.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('show'));
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}



async function renderChatHistory() {
  const list = document.getElementById('chatHistoryList');
  if (!list) return;
  let sessions = [];
  try {
    const res = await fetch(`${API}/api/sessions`);
    if (res.ok) {
      const data = await res.json();
      sessions = data.sessions || [];
    }
  } catch (_) {}
  if (!sessions.length) {
    list.innerHTML = `<div class="nav-item" style="font-size:0.8rem;padding:6px 10px;color:var(--text-dim);" data-i18n="noChats">${t('noChats')}</div>`;
    return;
  }
  list.innerHTML = sessions.map(h => {
    const dateStr = h.created_at ? new Date(h.created_at * 1000).toLocaleDateString() : (h.date || '');
    return `
    <a href="#" class="nav-item chat-history-item" data-session="${h.id}" style="font-size:0.8rem;padding:6px 10px;">
      <span style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1;">${escapeHtml(h.title || 'Untitled')}</span>
      <span style="font-size:0.65rem;color:var(--text-dim);margin-left:4px;white-space:nowrap;">${dateStr}</span>
    </a>
  `}).join('');
  list.querySelectorAll('.chat-history-item').forEach(item => {
    item.addEventListener('click', async (e) => {
      e.preventDefault();
      const sessionId = item.dataset.session;
      localStorage.setItem('session_id', sessionId);
      await loadSessionIntoChat(sessionId, item.querySelector('span')?.textContent);
    });
  });
}

async function renderPersonas() {
  const grid = document.getElementById('personaGrid');
  if (!grid) return;
  let personas = [];
  try {
    const res = await fetch(`${API}/api/personas`);
    if (res.ok) {
      const data = await res.json();
      personas = data.personas || [];
    }
  } catch (_) {}
  if (!personas.length) {
    grid.innerHTML = '<div style="padding:12px;color:var(--text-dim);font-size:0.85rem;">No personas configured.</div>';
    return;
  }
  grid.innerHTML = personas.map(p => `
    <div class="persona-card" data-id="${p.name}">
      <div class="emoji">${p.emoji || '🐄'}</div>
      <div class="name">${p.name}</div>
      <div class="desc">${p.description || ''}</div>
      <button class="btn btn-secondary persona-delete-btn" data-name="${p.name}" title="Delete">🗑️</button>
    </div>
  `).join('');
  grid.querySelectorAll('.persona-card').forEach(card => {
    card.addEventListener('click', (e) => {
      if (e.target.closest('.persona-delete-btn')) return;
      grid.querySelectorAll('.persona-card').forEach(c => c.classList.remove('active'));
      card.classList.add('active');
      const sel = document.getElementById('personaSelect');
      if (sel) sel.value = card.dataset.id;
    });
  });
  grid.querySelectorAll('.persona-delete-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      try {
        const res = await fetch(`${API}/api/personas/${encodeURIComponent(btn.dataset.name)}`, {
          method: 'DELETE',
          headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {}
        });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        await loadPersonasAndAgents();
        await renderPersonas();
        showToast('Persona deleted', 'success');
      } catch (e) {
        showToast('Failed to delete persona: ' + e.message, 'error');
      }
    });
  });
}

async function renderMcp() {
  const list = document.getElementById('mcpList');
  if (!list) return;
  let servers = [];
  try {
    const res = await fetch(`${API}/api/mcp/servers`);
    if (res.ok) {
      const data = await res.json();
      servers = data.servers || [];
    }
  } catch (_) {}
  if (!servers.length) {
    list.innerHTML = '<div style="padding:12px;color:var(--text-dim);font-size:0.85rem;">No MCP servers configured.</div>';
    return;
  }
  list.innerHTML = servers.map(m => `
    <div class="mcp-item">
      <div>
        <strong>${m.name}</strong>
        <div class="meta">${m.transport || 'stdio'} · ${m.status || 'idle'}</div>
      </div>
      <button class="btn btn-secondary">Test</button>
    </div>
  `).join('');
}

async function renderStatus() {
  const grid = document.getElementById('statusGrid');
  if (!grid) return;
  let statusItems = [];
  try {
    const res = await fetch(`${API}/api/status`);
    if (res.ok) {
      const data = await res.json();
      statusItems = [
        { label: 'Backend', value: 'Online', healthy: true },
        { label: 'Ollama', value: data.active_agent ? 'Connected' : 'Offline', healthy: !!data.active_agent },
        { label: 'Model', value: data.active_agent || 'None', healthy: !!data.active_agent },
        { label: 'PQC Keys', value: data.pqc_enabled ? 'Active' : 'Inactive', healthy: data.pqc_enabled },
        { label: 'Sandbox', value: data.sandbox_running ? 'Running' : 'Stopped', healthy: data.sandbox_running },
        { label: 'Policy Rules', value: String((data.policy_rules || []).length), healthy: true },
      ];
      const ruleCount = document.getElementById('ruleCount');
      if (ruleCount) ruleCount.textContent = String((data.policy_rules || []).length);
      const ollamaDot = document.getElementById('ollamaDot');
      if (ollamaDot) ollamaDot.classList.toggle('green', !!data.active_agent);
    }
  } catch (_) {}
  if (!statusItems.length) {
    grid.innerHTML = '<div style="padding:12px;color:var(--text-dim);font-size:0.85rem;">Status unavailable.</div>';
    return;
  }
  grid.innerHTML = statusItems.map(s => `
    <div class="status-card">
      <div class="label">${s.label}</div>
      <div class="value" style="color:${s.healthy ? '#51cf66' : '#ff6b6b'}">${s.value}</div>
    </div>
  `).join('');
}

async function renderMemories() {
  const facts = document.getElementById('factsList');
  const prefs = document.getElementById('preferencesList');
  let memories = [];
  try {
    const res = await fetch(`${API}/api/memory`);
    if (res.ok) {
      const data = await res.json();
      memories = data.entries || data.memories || [];
    }
  } catch (_) {}
  const emptyHtml = `<div class="memory-item" style="color:var(--text-dim);">No memories yet</div>`;
  if (facts) {
    const factItems = memories.filter(m => (m.memory_type || m.type || '').toLowerCase() === 'fact');
    facts.innerHTML = factItems.length ? factItems.map(m => `
      <div class="memory-item"><span><strong>${m.key}</strong>: ${m.value}</span><button>Delete</button></div>
    `).join('') : emptyHtml;
  }
  if (prefs) {
    const prefItems = memories.filter(m => (m.memory_type || m.type || '').toLowerCase() === 'preference');
    prefs.innerHTML = prefItems.length ? prefItems.map(m => `
      <div class="memory-item"><span><strong>${m.key}</strong>: ${m.value}</span><button>Delete</button></div>
    `).join('') : emptyHtml;
  }
}

async function renderMemoryQueue() {
  const list = document.getElementById('queueList');
  if (!list) return;
  list.innerHTML = '<div style="color:var(--text-dim);padding:1rem;">Loading queue...</div>';
  let proposals = [];
  try {
    const res = await fetch(`${API}/api/memory/queue`);
    if (res.ok) {
      const data = await res.json();
      proposals = data.proposals || [];
    }
  } catch (_) {}
  if (!proposals.length) {
    list.innerHTML = '<div style="color:var(--text-dim);padding:1rem;">No pending approvals.</div>';
    return;
  }
  list.innerHTML = proposals.map(p => `
    <div class="queue-item" data-id="${p.id}">
      <div style="flex:1;">
        <div><strong>${escapeHtml(p.memory_type || 'memory')}</strong>: ${escapeHtml(p.key || '')}</div>
        <div style="font-size:0.8rem;color:var(--text-dim);margin-top:2px;">${escapeHtml(String(p.value || ''))}</div>
        ${p.justification ? `<div style="font-size:0.75rem;color:var(--text-dim);margin-top:4px;font-style:italic;">${escapeHtml(p.justification)}</div>` : ''}
      </div>
      <div style="display:flex;gap:6px;">
        <button class="btn btn-primary queue-approve-btn" data-id="${p.id}" style="padding:4px 10px;font-size:0.75rem;">Approve</button>
        <button class="btn btn-secondary queue-reject-btn" data-id="${p.id}" style="padding:4px 10px;font-size:0.75rem;">Reject</button>
      </div>
    </div>
  `).join('');
  list.querySelectorAll('.queue-approve-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const id = btn.dataset.id;
      try {
        const res = await fetch(`${API}/api/memory/queue/${id}/approve`, { method: 'POST', headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {} });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        await renderMemoryQueue();
        await renderMemories();
        showToast('Approved', 'success');
      } catch (e) { showToast('Failed: ' + e.message, 'error'); }
    });
  });
  list.querySelectorAll('.queue-reject-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const id = btn.dataset.id;
      try {
        const res = await fetch(`${API}/api/memory/queue/${id}/reject`, { method: 'POST', headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {} });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        await renderMemoryQueue();
        showToast('Rejected', 'info');
      } catch (e) { showToast('Failed: ' + e.message, 'error'); }
    });
  });
}

async function renderPresets() {
  const grid = document.getElementById('presetGrid');
  if (!grid) return;
  grid.innerHTML = '<div style="color:var(--text-dim);padding:1rem;">Loading presets...</div>';
  let presets = [];
  try {
    const res = await fetch(`${API}/api/presets`);
    if (res.ok) {
      const data = await res.json();
      presets = Array.isArray(data) ? data : (data.presets || []);
    }
  } catch (_) {}
  if (!presets.length) {
    grid.innerHTML = '<div style="color:var(--text-dim);padding:1rem;">No presets available.</div>';
    return;
  }
  grid.innerHTML = presets.map(p => `
    <div class="preset-card" data-name="${p.name}">
      <div>
        <strong>${p.name}</strong>
        <div class="meta">${p.description || ''}</div>
        <div class="meta">${p.provider || ''} · ${p.model || ''}</div>
      </div>
      <button class="btn btn-secondary preset-install-btn">Install</button>
    </div>
  `).join('');
  grid.querySelectorAll('.preset-install-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const card = btn.closest('.preset-card');
      const name = card?.dataset.name;
      if (!name) return;
      btn.textContent = 'Installing...';
      btn.disabled = true;
      try {
        const headers = { 'Content-Type': 'application/json' };
        if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
        const res = await fetch(`${API}/api/presets/${encodeURIComponent(name)}/install`, {
          method: 'POST',
          headers
        });
        if (!res.ok) throw new Error('Status ' + res.status);
        showToast('Preset "' + name + '" installed', 'success');
        btn.textContent = 'Installed';
      } catch (e) {
        showToast('Failed to install preset: ' + e.message, 'error');
        btn.textContent = 'Install';
        btn.disabled = false;
      }
    });
  });
}

async function renderGraph() {
  const container = document.getElementById('graphContainer');
  if (!container) return;
  container.innerHTML = '<div style="text-align:center;color:var(--text-dim);padding:2rem;">Loading graph...</div>';
  let data;
  try {
    const res = await fetch(`${API}/api/knowledge-graph`);
    if (!res.ok) throw new Error('Failed to fetch');
    data = await res.json();
  } catch (_) {
    container.innerHTML = '<div style="text-align:center;color:var(--text-dim);padding:2rem;">Unable to load knowledge graph.</div>';
    return;
  }
  const nodes = Array.isArray(data.nodes) ? data.nodes : [];
  const edges = Array.isArray(data.edges) ? data.edges : [];
  if (nodes.length === 0) {
    container.innerHTML = '<div style="text-align:center;color:var(--text-dim);padding:2rem;">No graph data yet.</div>';
    return;
  }

  const width = container.clientWidth || 800;
  const height = container.clientHeight || 500;
  const nodeRadius = 40;
  const padding = nodeRadius + 20;

  // Simple force-directed-ish layout: place nodes in a circle
  const positions = {};
  nodes.forEach((node, i) => {
    const angle = (2 * Math.PI * i) / Math.max(nodes.length, 1);
    const cx = width / 2;
    const cy = height / 2;
    const rx = Math.min(width, height) / 2 - padding;
    const ry = rx;
    positions[node.id || node.key || i] = {
      x: cx + rx * Math.cos(angle),
      y: cy + ry * Math.sin(angle)
    };
  });

  // Build HTML
  const wrapper = document.createElement('div');
  wrapper.style.position = 'relative';
  wrapper.style.width = width + 'px';
  wrapper.style.height = height + 'px';
  wrapper.style.overflow = 'hidden';

  // Draw edges as rotated divs
  edges.forEach(edge => {
    const from = positions[edge.from || edge.source];
    const to = positions[edge.to || edge.target];
    if (!from || !to) return;
    const dx = to.x - from.x;
    const dy = to.y - from.y;
    const length = Math.sqrt(dx * dx + dy * dy);
    const angle = Math.atan2(dy, dx) * (180 / Math.PI);
    const line = document.createElement('div');
    line.style.position = 'absolute';
    line.style.left = from.x + 'px';
    line.style.top = from.y + 'px';
    line.style.width = length + 'px';
    line.style.height = '2px';
    line.style.background = 'var(--border)';
    line.style.transformOrigin = '0 50%';
    line.style.transform = `rotate(${angle}deg)`;
    wrapper.appendChild(line);
  });

  // Draw nodes
  nodes.forEach(node => {
    const pos = positions[node.id || node.key];
    if (!pos) return;
    const el = document.createElement('div');
    el.style.position = 'absolute';
    el.style.left = (pos.x - nodeRadius) + 'px';
    el.style.top = (pos.y - nodeRadius) + 'px';
    el.style.width = (nodeRadius * 2) + 'px';
    el.style.height = (nodeRadius * 2) + 'px';
    el.style.borderRadius = '50%';
    el.style.background = 'var(--accent)';
    el.style.display = 'flex';
    el.style.alignItems = 'center';
    el.style.justifyContent = 'center';
    el.style.fontSize = '0.7rem';
    el.style.color = '#fff';
    el.style.textAlign = 'center';
    el.style.padding = '4px';
    el.style.boxSizing = 'border-box';
    el.style.wordBreak = 'break-word';
    el.style.cursor = 'default';
    el.title = node.label || node.key || '';
    el.textContent = node.label || node.key || node.id || '';
    wrapper.appendChild(el);
  });

  container.innerHTML = '';
  container.appendChild(wrapper);
}

// ===== Event Listeners =====
document.addEventListener('DOMContentLoaded', async () => {
  async function loadSessionIntoChat(sessionId, titleFallback) {
    const messagesContainer = document.getElementById('messages');
    if (!messagesContainer || !sessionId) return;
    try {
      const res = await fetch(`${API}/api/sessions/${encodeURIComponent(sessionId)}`);
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const session = await res.json();
      messagesContainer.innerHTML = '';
      if (session.messages && session.messages.length) {
        session.messages.forEach(m => addMessage(m.content || m.text || '', m.role === 'user'));
      } else {
        messagesContainer.innerHTML = `<div class="message ai">Loaded session: <strong>${titleFallback || session.title || 'Untitled'}</strong></div>`;
      }
    } catch (err) {
      messagesContainer.innerHTML = `<div class="message ai">Could not load session: ${err.message}</div>`;
    }
  }

  initTheme();
  const savedLang = localStorage.getItem('language');
  if (savedLang) document.documentElement.setAttribute('lang', savedLang);
  loadChat();
  const messagesEl = document.getElementById('messages');
  if (messagesEl && (!messagesEl.children.length || messagesEl.querySelector('.welcome-message'))) {
    showWelcome();
  }
  await renderPersonas();
  document.getElementById('personaCreateBtn')?.addEventListener('click', async () => {
    const emoji = document.getElementById('personaEmojiInput')?.value.trim() || '🐄';
    const name = document.getElementById('personaNameInput')?.value.trim();
    const desc = document.getElementById('personaDescInput')?.value.trim();
    const prompt = document.getElementById('personaPromptInput')?.value.trim();
    if (!name || !prompt) {
      showToast('Name and system prompt are required', 'error');
      return;
    }
    try {
      const res = await fetch(`${API}/api/personas`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) },
        body: JSON.stringify({ name, emoji, description: desc, system_prompt: prompt })
      });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      document.getElementById('personaEmojiInput').value = '';
      document.getElementById('personaNameInput').value = '';
      document.getElementById('personaDescInput').value = '';
      document.getElementById('personaPromptInput').value = '';
      await loadPersonasAndAgents();
      await renderPersonas();
      showToast('Persona created', 'success');
    } catch (e) {
      showToast('Failed to create persona: ' + e.message, 'error');
    }
  });
  await renderMcp();
  await renderStatus();
  await renderMemories();
  await renderChatHistory();
  await renderPresets();

  // Update version badge and status sidebar
  async function updateStatus() {
    const offlineEl = document.querySelector('.offline-indicator');
    try {
      const [statusRes, versionRes] = await Promise.all([
        fetch(`${API}/api/status`),
        fetch(`${API}/api/version`)
      ]);
      if (!statusRes.ok) {
        if (offlineEl) offlineEl.style.display = 'block';
        return;
      }
      if (offlineEl) offlineEl.style.display = 'none';
      const data = await statusRes.json();
      if (versionRes.ok) {
        const v = await versionRes.json();
        const badge = document.getElementById('versionBadge');
        if (badge && v.version) badge.textContent = 'v' + v.version;
        const display = document.getElementById('versionDisplay');
        if (display && v.version) display.textContent = 'v' + v.version;
      }
      const dot = document.getElementById('ollamaDot');
      if (dot) dot.classList.toggle('green', !!data.active_agent);
      const el = document.getElementById('ruleCount');
      if (el) el.textContent = String((data.policy_rules || []).length);
    } catch (_) {
      if (offlineEl) offlineEl.style.display = 'block';
    }
  }
  updateStatus();
  setInterval(updateStatus, 30000);

  // Name AI modal
  const nameAiForm = document.querySelector('#nameAiModal form');
  if (nameAiForm) {
    nameAiForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const val = document.getElementById('aiNameInput').value.trim();
      const lang = document.getElementById('languageSelect')?.value;
      if (val) {
        aiName = val;
        localStorage.setItem('aiName', aiName);
        document.getElementById('input').placeholder = t('messagePlaceholder', { name: aiName });
      }
      if (lang) {
        localStorage.setItem('language', lang);
        document.documentElement.setAttribute('lang', lang);
      }
      applyTranslations();
      const messages = document.getElementById('messages');
      if (messages && messages.querySelector('.welcome-message')) {
        showWelcome();
      }
      try {
        const headers = { 'Content-Type': 'application/json' };
        if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
        await fetch(`${API}/api/settings`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ ai_name: val || aiName, language: lang || '' })
        });
      } catch (_) {}
      closeModal('nameAiModal');
    });
  }

  // No auth required — initialize immediately
  loadPersonasAndAgents();

  // Agent select change → update privacy warning
  const agentSelectEl = document.getElementById('agentSelect');
  if (agentSelectEl) {
    agentSelectEl.addEventListener('change', updateCloudPrivacyWarning);
  }

  // Update AI name in UI
  if (aiName) {
    const welcomeH2 = document.querySelector('.welcome-message h2');
    if (welcomeH2) welcomeH2.textContent = '🐄 Welcome to ' + aiName;
    const inputEl = document.getElementById('input');
    if (inputEl) inputEl.placeholder = 'Message ' + aiName + '...';
    document.title = aiName + ' — Secure AI Agent';
  }

  // Highlight current theme in picker
  document.querySelectorAll('.theme-option').forEach(opt => {
    opt.classList.toggle('selected', opt.dataset.theme === currentTheme);
  });

  // Tabs
  document.querySelectorAll('.nav-item[data-tab]').forEach(el => {
    el.addEventListener('click', async (e) => {
      e.preventDefault();
      await switchTab(el.dataset.tab);
    });
  });

  // Chat
  const sendBtn = document.getElementById('send');
  const chatInput = document.getElementById('input');
  const messagesContainer = document.getElementById('messages');
  const scrollBottomBtn = document.getElementById('scrollBottomBtn');
  if (sendBtn) sendBtn.addEventListener('click', sendChatStream);
  if (chatInput) {
    const draft = localStorage.getItem('chat_draft');
    if (draft) chatInput.value = draft;
    chatInput.addEventListener('input', () => {
      localStorage.setItem('chat_draft', chatInput.value);
      chatInput.style.height = 'auto';
      chatInput.style.height = Math.min(chatInput.scrollHeight, 120) + 'px';
      const sendBtn2 = document.getElementById('send');
      if (sendBtn2) sendBtn2.classList.toggle('pulse', chatInput.value.trim().length > 0);
      const meta = document.getElementById('inputMeta');
      if (meta) {
        const len = chatInput.value.length;
        meta.textContent = len > 0 ? len + ' chars' : '';
      }
    });
    chatInput.addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChatStream(); }
    });
  }
  if (messagesContainer) {
    messagesContainer.addEventListener('scroll', updateScrollButton);
  }
  if (scrollBottomBtn) {
    scrollBottomBtn.addEventListener('click', () => {
      messagesContainer.scrollTop = messagesContainer.scrollHeight;
      updateScrollButton();
    });
  }

  // Attachment menu (+ button dropdown)
  const attachBtn = document.getElementById('attachBtn');
  const attachDropdown = document.getElementById('attachDropdown');
  if (attachBtn && attachDropdown) {
    attachBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      attachDropdown.classList.toggle('open');
    });
    // Close dropdown when clicking outside
    document.addEventListener('click', (e) => {
      if (!attachDropdown.contains(e.target) && e.target !== attachBtn) {
        attachDropdown.classList.remove('open');
      }
    });
    // Handle dropdown option clicks
    attachDropdown.querySelectorAll('.attach-option').forEach((opt) => {
      opt.addEventListener('click', (e) => {
        e.stopPropagation();
        const action = opt.dataset.action;
        attachDropdown.classList.remove('open');
        if (action === 'file') {
          document.getElementById('fileInput')?.click();
        } else if (action === 'image') {
          document.getElementById('imageInput')?.click();
        }
      });
    });
  }

  // File upload
  const fileInput = document.getElementById('fileInput');
  const inputMeta = document.getElementById('inputMeta');
  if (fileInput) {
    fileInput.addEventListener('change', async () => {
      const file = fileInput.files[0];
      if (!file) return;
      if (inputMeta) inputMeta.textContent = '📎 Uploading ' + file.name + '...';
      const data = await uploadFile(file);
      if (data) {
        addMessage('✅ Uploaded **' + file.name + '** — ' + data.mime_type + ' (' + (data.size / 1024).toFixed(1) + ' KB)', false);
        if (inputMeta) inputMeta.textContent = '📎 ' + file.name + ' uploaded';
        setTimeout(() => { if (inputMeta) inputMeta.textContent = ''; }, 3000);
      } else {
        addMessage('❌ Failed to upload **' + file.name + '**', false);
        if (inputMeta) inputMeta.textContent = '';
      }
      fileInput.value = '';
    });
  }

  // Image attachment for multi-modal chat
  const imageInput = document.getElementById('imageInput');
  if (imageInput) {
    imageInput.addEventListener('change', () => {
      const file = imageInput.files[0];
      if (!file) return;
      attachedImage = file;
      if (inputMeta) inputMeta.innerHTML = '🖼️ ' + escapeHtml(file.name) + ' <button type="button" id="clearImageBtn" style="background:none;border:none;color:var(--accent);cursor:pointer;margin-left:6px;">✕</button>';
      const clearBtn = document.getElementById('clearImageBtn');
      if (clearBtn) clearBtn.addEventListener('click', clearAttachedImage);
      imageInput.value = '';
    });
  }
  function clearAttachedImage() {
    attachedImage = null;
    if (inputMeta) inputMeta.textContent = '';
  }
  window.clearAttachedImage = clearAttachedImage;

  // Voice input using Web Speech API with backend STT fallback
  const voiceBtn = document.getElementById('voiceBtn');
  if (voiceBtn) {
    let mediaRecorder = null;
    let audioChunks = [];
    let recording = false;
    let webSpeechRec = null;

    function startWebSpeech(input) {
      const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
      if (!SpeechRecognition) {
        showToast('Local STT is not configured. Run `muccheai setup` to install whisper, or install it manually with `pip install openai-whisper`.', 'error');
        return;
      }
      const langMap = { en: 'en-US', pt: 'pt-BR', zh: 'zh-CN' };
      webSpeechRec = new SpeechRecognition();
      const lang = document.documentElement.getAttribute('lang') || 'en';
      webSpeechRec.lang = langMap[lang] || lang || 'en-US';
      webSpeechRec.interimResults = true;
      webSpeechRec.continuous = true;
      webSpeechRec.onstart = () => {
        voiceBtn.classList.add('active', 'pulse');
        showToast('Listening via browser...', 'info');
      };
      webSpeechRec.onend = () => {
        voiceBtn.classList.remove('active', 'pulse');
      };
      webSpeechRec.onresult = (e) => {
        let final = '';
        let interim = '';
        for (let i = e.resultIndex; i < e.results.length; i++) {
          const t = e.results[i][0].transcript;
          if (e.results[i].isFinal) final += t + ' ';
          else interim += t;
        }
        input.value = (input.value ? input.value + ' ' : '') + final + interim;
        input.dispatchEvent(new Event('input'));
      };
      webSpeechRec.onerror = (e) => {
        showToast('Browser speech error: ' + e.error, 'error');
        voiceBtn.classList.remove('active', 'pulse');
      };
      input.dataset.voiceFinal = '';
      try { webSpeechRec.start(); } catch (err) { showToast('Could not start microphone: ' + err.message, 'error'); }
    }

    function stopWebSpeech() {
      if (webSpeechRec) { try { webSpeechRec.stop(); } catch (_) {} webSpeechRec = null; }
    }

    async function startRecording() {
      const input = document.getElementById('input');
      if (!input) return;
      try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        mediaRecorder = new MediaRecorder(stream);
        audioChunks = [];
        mediaRecorder.ondataavailable = (e) => { if (e.data.size > 0) audioChunks.push(e.data); };
        mediaRecorder.onstop = async () => {
          voiceBtn.classList.remove('active', 'pulse');
          recording = false;
          const blob = new Blob(audioChunks, { type: 'audio/webm' });
          const formData = new FormData();
          formData.append('audio', blob, 'voice.webm');
          const headers = {};
          if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
          try {
            const res = await fetch(`${API}/api/stt`, { method: 'POST', headers, body: formData });
            if (!res.ok) {
              let msg = 'Local STT failed (' + res.status + ')';
              try { const err = await res.json(); if (err.error) msg = err.error; } catch (_) {}
              throw new Error(msg);
            }
            const data = await res.json();
            input.value = (input.value ? input.value + ' ' : '') + (data.transcription || '');
            input.dispatchEvent(new Event('input'));
          } catch (e) {
            showToast(e.message + '. Falling back to browser speech...', 'warning');
            startWebSpeech(input);
          }
        };
        mediaRecorder.start();
        recording = true;
        voiceBtn.classList.add('active', 'pulse');
        showToast('Recording... click again to stop', 'info');
      } catch (e) {
        showToast('Microphone error: ' + e.message, 'error');
      }
    }

    voiceBtn.addEventListener('click', () => {
      if (recording && mediaRecorder) {
        mediaRecorder.stop();
        mediaRecorder.stream.getTracks().forEach(t => t.stop());
      } else if (webSpeechRec) {
        stopWebSpeech();
      } else {
        startRecording();
      }
    });
  }

  // Settings button in sidebar
  const settingsBtn = document.querySelector('.nav-item:not([data-tab])');
  if (settingsBtn) settingsBtn.addEventListener('click', e => { e.preventDefault(); openSettings(); });

  // Close modals and slide panels via X buttons
  document.querySelectorAll('.modal .btn-icon, .api-key-modal .btn-icon, .slide-panel-header .btn-icon').forEach(btn => {
    btn.addEventListener('click', () => {
      const modal = btn.closest('.modal, .api-key-modal');
      if (modal) modal.style.display = 'none';
      const panel = btn.closest('.slide-panel');
      const backdrop = document.getElementById('apiPanelBackdrop');
      if (panel) panel.classList.remove('open');
      if (backdrop) backdrop.classList.remove('open');
    });
  });

  // Slide panel
  const apiPanelToggle = document.getElementById('apiPanelToggleBtn');
  const apiPanel = document.getElementById('apiPanel');
  const apiBackdrop = document.getElementById('apiPanelBackdrop');
  if (apiPanelToggle) {
    apiPanelToggle.addEventListener('click', () => {
      apiPanel.classList.toggle('open');
      apiBackdrop.classList.toggle('open');
    });
  }
  if (apiBackdrop) {
    apiBackdrop.addEventListener('click', () => {
      apiPanel.classList.remove('open');
      apiBackdrop.classList.remove('open');
    });
  }

  // Logout
  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) logoutBtn.addEventListener('click', logout);

  // Dark mode / theme toggle button
  const darkModeBtn = document.getElementById('darkModeBtn');
  if (darkModeBtn) {
    darkModeBtn.addEventListener('click', () => {
      showThemePicker();
    });
  }

  // New chat
  const newChatBtn = document.getElementById('newChatBtn');
  if (newChatBtn) {
    newChatBtn.addEventListener('click', () => {
      showWelcome();
      clearChatStorage();
      localStorage.removeItem('session_id');
    });
  }

  // Theme picker options
  let previewTheme = null;
  document.querySelectorAll('.theme-option').forEach(opt => {
    opt.addEventListener('click', () => {
      applyTheme(opt.dataset.theme);
      document.querySelectorAll('.theme-option').forEach(o => o.classList.remove('selected'));
      opt.classList.add('selected');
      const modal = document.getElementById('themePickerModal');
      if (modal) modal.style.display = 'none';
      previewTheme = null;
    });
    opt.addEventListener('mouseenter', () => {
      previewTheme = currentTheme;
      applyTheme(opt.dataset.theme);
    });
    opt.addEventListener('mouseleave', () => {
      if (previewTheme) applyTheme(previewTheme);
      previewTheme = null;
    });
  });

  // Rename AI from settings
  const renameAiBtn = document.getElementById('renameAiBtn');
  if (renameAiBtn) {
    renameAiBtn.addEventListener('click', () => {
      const val = document.getElementById('settingAiName').value.trim();
      if (val) {
        aiName = val;
        localStorage.setItem('aiName', aiName);
        document.querySelector('.welcome-message h2').textContent = '🐄 Welcome to ' + aiName;
        document.getElementById('input').placeholder = 'Message ' + aiName + '...';
      }
    });
  }

  // Theme picker close controls
  const themePickerModal = document.getElementById('themePickerModal');
  const themePickerClose = document.getElementById('themePickerClose');
  if (themePickerClose && themePickerModal) {
    themePickerClose.addEventListener('click', () => {
      themePickerModal.style.display = 'none';
    });
  }
  if (themePickerModal) {
    themePickerModal.addEventListener('click', (e) => {
      if (e.target === themePickerModal) themePickerModal.style.display = 'none';
    });
  }

  // Change theme button in settings
  const changeThemeBtn = document.getElementById('changeThemeBtn');
  if (changeThemeBtn) {
    changeThemeBtn.addEventListener('click', () => {
      showThemePicker();
    });
  }

  // Persona switch
  const personaSelect = document.getElementById('personaSelect');
  if (personaSelect) {
    personaSelect.addEventListener('change', async () => {
      const personaId = personaSelect.value;
      try {
        const headers = { 'Content-Type': 'application/json' };
        if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
        const res = await fetch(`${API}/api/personas/switch`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ name: personaId })
        });
        if (!res.ok) throw new Error('Status ' + res.status);
        const option = personaSelect.options[personaSelect.selectedIndex];
        const personaName = option ? option.textContent.trim() : '';
        const topbarPersona = document.getElementById('topbarPersona');
        if (topbarPersona) topbarPersona.textContent = personaName;
        showToast('Persona switched to ' + personaName, 'success');
      } catch (e) {
        showToast('Failed to switch persona: ' + e.message, 'error');
      }
    });
  }

  // Temperature slider
  const tempSlider = document.getElementById('settingTemp');
  if (tempSlider) {
    tempSlider.addEventListener('input', e => {
      document.getElementById('tempValue').textContent = e.target.value;
    });
  }

  // Sound notifications toggle
  const soundToggle = document.getElementById('settingSound');
  if (soundToggle) {
    soundToggle.checked = soundEnabled;
    soundToggle.addEventListener('change', e => {
      setSoundEnabled(e.target.checked);
      if (e.target.checked) playNotificationSound();
    });
  }

  // Auto-scroll toggle
  const autoScrollToggle = document.getElementById('settingAutoScroll');
  if (autoScrollToggle) {
    autoScrollToggle.checked = autoScrollEnabled;
    autoScrollToggle.addEventListener('change', e => {
      autoScrollEnabled = e.target.checked;
      localStorage.setItem('autoScrollEnabled', String(autoScrollEnabled));
      showToast(autoScrollEnabled ? 'Auto-scroll enabled' : 'Auto-scroll disabled', 'info');
    });
  }

  // Compact mode toggle
  const compactToggle = document.getElementById('settingCompact');
  if (compactToggle) {
    compactToggle.checked = localStorage.getItem('compactMode') === 'true';
    if (compactToggle.checked) document.body.classList.add('compact-mode');
    compactToggle.addEventListener('change', e => {
      document.body.classList.toggle('compact-mode', e.target.checked);
      localStorage.setItem('compactMode', String(e.target.checked));
      showToast(e.target.checked ? 'Compact mode enabled' : 'Compact mode disabled', 'info');
    });
  }

  async function loadSettings() {
    try {
      const res = await fetch(`${API}/api/settings`);
      if (!res.ok) return;
      const s = await res.json();
      const langEl = document.getElementById('settingLanguage');
      if (langEl && s.language) langEl.value = s.language;
      const nameEl = document.getElementById('settingAiName');
      if (nameEl && s.ai_name) nameEl.value = s.ai_name;
      const modelEl = document.getElementById('settingModel');
      if (modelEl && s.model) modelEl.value = s.model;
      const tempEl = document.getElementById('settingTemp');
      if (tempEl && s.temperature !== undefined) tempEl.value = s.temperature;
      const maxTokensEl = document.getElementById('settingMaxTokens');
      if (maxTokensEl && s.max_tokens !== undefined) maxTokensEl.value = s.max_tokens;
      const soundEl = document.getElementById('settingSound');
      if (soundEl && s.sound_enabled !== undefined) soundEl.checked = s.sound_enabled;
      const scrollEl = document.getElementById('settingAutoScroll');
      if (scrollEl && s.auto_scroll !== undefined) scrollEl.checked = s.auto_scroll;
      const compactEl = document.getElementById('settingCompact');
      if (compactEl && s.compact_mode !== undefined) compactEl.checked = s.compact_mode;
      if (s.ai_name) {
        aiName = s.ai_name;
        localStorage.setItem('aiName', s.ai_name);
      }
      if (s.language) {
        localStorage.setItem('language', s.language);
        document.documentElement.setAttribute('lang', s.language);
      }
    } catch (_) {}
  }
  loadSettings();

  // Save Settings button
  const saveSettingsBtn = document.querySelector('#settingsModal .btn-row .btn-primary');
  if (saveSettingsBtn) {
    saveSettingsBtn.addEventListener('click', async () => {
      const settings = {
        language: document.getElementById('settingLanguage')?.value || 'en',
        ai_name: document.getElementById('settingAiName')?.value?.trim() || aiName,
        model: document.getElementById('settingModel')?.value || '',
        temperature: parseFloat(document.getElementById('settingTemp')?.value || '0.7'),
        max_tokens: parseInt(document.getElementById('settingMaxTokens')?.value || '1024', 10),
        sound_enabled: document.getElementById('settingSound')?.checked ?? true,
        auto_scroll: document.getElementById('settingAutoScroll')?.checked ?? true,
        compact_mode: document.getElementById('settingCompact')?.checked ?? false,
      };
      try {
        const headers = { 'Content-Type': 'application/json' };
        if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
        const res = await fetch(`${API}/api/settings`, {
          method: 'POST',
          headers,
          body: JSON.stringify(settings)
        });
        if (!res.ok) throw new Error('Status ' + res.status);
        showToast('Settings saved', 'success');
        await loadSettings();
      } catch (e) {
        showToast('Failed to save settings: ' + e.message, 'error');
      }
    });
  }

  // Language select
  const languageSelect = document.getElementById('settingLanguage');
  if (languageSelect) {
    languageSelect.addEventListener('change', () => {
      localStorage.setItem('language', languageSelect.value);
      document.documentElement.setAttribute('lang', languageSelect.value);
      applyTranslations();
    });
  }
  applyTranslations();
  initModalOutsideClick();

  // Thinking panel expand/collapse
  const thinkingPanel = document.getElementById('thinkingPanel');
  const thinkingPanelHeader = thinkingPanel?.querySelector('.thinking-panel-header');
  if (thinkingPanelHeader) {
    thinkingPanelHeader.addEventListener('click', () => {
      thinkingPanel.classList.toggle('expanded');
    });
  }

  // Status sidebar collapse/expand
  const statusToggle = document.getElementById('statusToggle');
  const statusSidebar = document.getElementById('statusSidebar');
  if (statusToggle && statusSidebar) {
    statusToggle.addEventListener('click', () => {
      statusSidebar.classList.toggle('collapsed');
      localStorage.setItem('statusSidebarCollapsed', statusSidebar.classList.contains('collapsed') ? '1' : '0');
    });
    if (localStorage.getItem('statusSidebarCollapsed') === '1') {
      statusSidebar.classList.add('collapsed');
    }
  }

  // Sidebar toggle for mobile and desktop
  const sidebarToggle = document.getElementById('sidebarToggleBtn');
  const sidebar = document.querySelector('.sidebar');
  if (sidebarToggle && sidebar) {
    sidebarToggle.addEventListener('click', () => {
      if (window.innerWidth <= 768) {
        sidebar.classList.toggle('open');
      } else {
        sidebar.classList.toggle('closed');
        document.querySelector('.app-layout')?.classList.toggle('sidebar-closed', sidebar.classList.contains('closed'));
      }
    });
  }

  // Close sidebar when clicking outside on mobile
  document.addEventListener('click', e => {
    if (window.innerWidth <= 768 && sidebar && sidebar.classList.contains('open')) {
      if (!sidebar.contains(e.target) && e.target !== sidebarToggle) {
        sidebar.classList.remove('open');
      }
    }
  });

  // Research modal
  const runResearchBtn = document.getElementById('runResearchBtn');
  if (runResearchBtn) {
    runResearchBtn.addEventListener('click', async () => {
      const query = document.getElementById('researchQuery').value.trim();
      if (!query) return;
      const result = document.getElementById('researchResult');
      const loading = document.getElementById('researchLoading');
      if (loading) loading.style.display = 'block';
      if (result) result.textContent = '';
      try {
        const res = await fetch(`${API}/api/search?q=` + encodeURIComponent(query));
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        const items = data.results || [];
        if (loading) loading.style.display = 'none';
        if (!items.length) {
          if (result) result.textContent = 'No results found for "' + query + '".';
          return;
        }
        const lines = items.slice(0, 10).map(r => `• [${r.type}] ${r.title}\n  ${(r.content || '').substring(0, 160)}`);
        if (result) result.textContent = `Results for "${query}":\n\n${lines.join('\n\n')}`;
      } catch (e) {
        if (loading) loading.style.display = 'none';
        if (result) result.textContent = 'Research failed: ' + e.message;
      }
    });
  }

  // Memory add form
  const memoryAddBtn = document.querySelector('#memory-subtab-memories .memory-add-form button');
  if (memoryAddBtn) {
    memoryAddBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      const type = document.getElementById('memoryTypeSelect').value;
      const key = document.getElementById('memoryKeyInput').value.trim();
      const value = document.getElementById('memoryValueInput').value.trim();
      if (!key || !value) return;
      try {
        const memoryType = type.charAt(0).toUpperCase() + type.slice(1);
        const res = await fetch(`${API}/api/memory`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) },
          body: JSON.stringify({ key, value, memory_type: memoryType })
        });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        await renderMemories();
        document.getElementById('memoryKeyInput').value = '';
        document.getElementById('memoryValueInput').value = '';
        showToast('Memory saved', 'success');
      } catch (e) {
        showToast('Failed to save memory: ' + e.message, 'error');
      }
    });
  }

  // Memory subtabs
  const subtabMemories = document.getElementById('subtab-memories');
  const subtabQueue = document.getElementById('subtab-queue');
  if (subtabMemories && subtabQueue) {
    subtabMemories.addEventListener('click', () => {
      subtabMemories.classList.add('active');
      subtabQueue.classList.remove('active');
      document.getElementById('memory-subtab-memories').style.display = 'block';
      document.getElementById('memory-subtab-queue').style.display = 'none';
    });
    subtabQueue.addEventListener('click', () => {
      subtabQueue.classList.add('active');
      subtabMemories.classList.remove('active');
      document.getElementById('memory-subtab-memories').style.display = 'none';
      document.getElementById('memory-subtab-queue').style.display = 'block';
      renderMemoryQueue();
    });
  }

  // MCP transport toggle
  const mcpTransport = document.getElementById('mcpTransport');
  const mcpStdioFields = document.getElementById('mcpStdioFields');
  const mcpHttpFields = document.getElementById('mcpHttpFields');
  if (mcpTransport) {
    mcpTransport.addEventListener('change', e => {
      const isHttp = e.target.value === 'http';
      if (mcpStdioFields) mcpStdioFields.style.display = isHttp ? 'none' : 'block';
      if (mcpHttpFields) mcpHttpFields.style.display = isHttp ? 'block' : 'none';
    });
  }

  // MCP add button
  const mcpAddBtn = document.getElementById('mcpAddBtn');
  if (mcpAddBtn) {
    mcpAddBtn.addEventListener('click', async () => {
      const name = document.getElementById('mcpName').value.trim();
      if (!name) return;
      const transport = document.getElementById('mcpTransport')?.value || 'stdio';
      const command = document.getElementById('mcpCommand')?.value.trim() || '';
      const url = document.getElementById('mcpUrl')?.value.trim() || '';
      const body = { name, transport };
      if (transport === 'http') body.url = url;
      else body.command = command;
      try {
        const res = await fetch(`${API}/api/mcp/servers`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) },
          body: JSON.stringify(body)
        });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        await renderMcp();
        document.getElementById('mcpName').value = '';
        showToast('MCP server added', 'success');
      } catch (e) {
        showToast('Failed to add MCP server: ' + e.message, 'error');
      }
    });
  }

  // Sidebar search
  const sidebarSearchPanel = document.getElementById('sidebarSearchPanel');
  const sidebarSearchInput = document.getElementById('sidebarSearchInput');
  const sidebarSearchClose = document.getElementById('sidebarSearchClose');
  const sidebarSearchResults = document.getElementById('sidebarSearchResults');
  const sidebarSearchEmpty = document.getElementById('sidebarSearchEmpty');

  function openSidebarSearch() {
    if (!sidebarSearchPanel) return;
    sidebarSearchPanel.classList.add('open');
    sidebarSearchInput?.focus();
  }
  function closeSidebarSearch() {
    if (!sidebarSearchPanel) return;
    sidebarSearchPanel.classList.remove('open');
    if (sidebarSearchInput) sidebarSearchInput.value = '';
    if (sidebarSearchResults) sidebarSearchResults.innerHTML = '';
    if (sidebarSearchEmpty) sidebarSearchEmpty.style.display = 'none';
  }
  function updateSidebarSearch(term) {
    if (!sidebarSearchResults || !sidebarSearchEmpty) return;
    const items = document.querySelectorAll('.chat-history-item');
    const lower = term.toLowerCase();
    let matchCount = 0;
    sidebarSearchResults.innerHTML = '';
    items.forEach(item => {
      const text = item.textContent.toLowerCase();
      if (!lower || text.includes(lower)) {
        const clone = item.cloneNode(true);
        clone.addEventListener('click', async (e) => {
          e.preventDefault();
          localStorage.setItem('session_id', clone.dataset.session);
          await loadSessionIntoChat(clone.dataset.session, clone.querySelector('span')?.textContent);
          closeSidebarSearch();
        });
        sidebarSearchResults.appendChild(clone);
        matchCount++;
      }
    });
    sidebarSearchEmpty.style.display = (term && matchCount === 0) ? 'block' : 'none';
  }

  const globalSearchBtn = document.getElementById('globalSearchBtn');
  if (globalSearchBtn) {
    globalSearchBtn.addEventListener('click', openSidebarSearch);
  }
  if (sidebarSearchClose) {
    sidebarSearchClose.addEventListener('click', closeSidebarSearch);
  }
  if (sidebarSearchInput) {
    sidebarSearchInput.addEventListener('input', e => updateSidebarSearch(e.target.value));
  }

  // Inline chat search (filter messages)
  let searchBox = null;
  document.addEventListener('keydown', e => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'f' && document.querySelector('.tab.active#tab-chat')) {
      e.preventDefault();
      if (!searchBox) {
        searchBox = document.createElement('div');
        searchBox.className = 'chat-search-box';
        searchBox.innerHTML = '<input type="text" placeholder="Find in chat..."><button>✕</button>';
        const input = searchBox.querySelector('input');
        const closeBtn = searchBox.querySelector('button');
        input.addEventListener('input', () => {
          const term = input.value.toLowerCase();
          document.querySelectorAll('.message').forEach(msg => {
            msg.style.opacity = term && !msg.textContent.toLowerCase().includes(term) ? '0.3' : '1';
          });
        });
        closeBtn.addEventListener('click', () => {
          document.querySelectorAll('.message').forEach(msg => msg.style.opacity = '1');
          searchBox.remove();
          searchBox = null;
        });
        document.querySelector('.chat-panel').appendChild(searchBox);
        input.focus();
      }
    }
  });

  // Research chats button
  const researchChatsBtn = document.getElementById('researchChatsBtn');
  if (researchChatsBtn) {
    researchChatsBtn.addEventListener('click', () => openModal('researchModal'));
  }

  // Share / digest / encrypt buttons
  document.getElementById('shareSessionBtn')?.addEventListener('click', async () => {
    const sessionId = currentSession();
    if (!sessionId) {
      showToast('No active session to share. Send a message first.', 'error');
      return;
    }
    try {
      const res = await fetch(`${API}/api/sessions/${encodeURIComponent(sessionId)}/share`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) }
      });
      if (!res.ok) {
        const body = await res.text().catch(() => '');
        throw new Error('HTTP ' + res.status + ' ' + body);
      }
      const data = await res.json();
      const token = data.share_token || data.token;
      const link = data.url || data.link || (token ? location.origin + '/share/' + token : '');
      if (!link) throw new Error('No share token returned');
      await navigator.clipboard.writeText(link);
      showToast('Session link copied to clipboard', 'success');
    } catch (e) {
      showToast('Share failed: ' + e.message, 'error');
    }
  });
  document.getElementById('copyChatBtn')?.addEventListener('click', () => {
    const messages = Array.from(document.querySelectorAll('.message'));
    let text = '';
    messages.forEach(m => {
      const role = m.classList.contains('user') ? 'User' : aiName;
      const raw = m.dataset.rawText || '';
      text += `${role}: ${raw}\n\n`;
    });
    navigator.clipboard.writeText(text.trim()).then(() => {
      showToast('Entire chat copied to clipboard', 'success');
    }).catch(() => showToast('Copy failed', 'error'));
  });
  document.getElementById('digestSessionBtn')?.addEventListener('click', () => {
    const messages = Array.from(document.querySelectorAll('.message'));
    let md = '# Chat Export\n\n';
    messages.forEach(m => {
      const role = m.classList.contains('user') ? 'User' : aiName;
      const text = m.textContent.replace(/\d{1,2}:\d{2}/, '').trim();
      md += `## ${role}\n${text}\n\n`;
    });
    const blob = new Blob([md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'chat-export.md';
    a.click();
    URL.revokeObjectURL(url);
    showToast('Chat exported as Markdown', 'success');
  });
  document.getElementById('clearChatBtn')?.addEventListener('click', () => {
    if (confirm('Clear all messages? This cannot be undone.')) {
      showWelcome();
      clearChatStorage();
      localStorage.removeItem('session_id');
      showToast('Chat cleared', 'info');
    }
  });
  document.getElementById('encryptShareBtn')?.addEventListener('click', async () => {
    const sessionId = currentSession();
    if (!sessionId) {
      showToast('No active session to share. Send a message first.', 'error');
      return;
    }
    try {
      const res = await fetch(`${API}/api/sessions/${encodeURIComponent(sessionId)}/encrypt-share`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) }
      });
      if (!res.ok) {
        const body = await res.text().catch(() => '');
        throw new Error('HTTP ' + res.status + ' ' + body);
      }
      const data = await res.json();
      const token = data.share_token || data.token;
      const link = data.url || data.link || (token ? location.origin + '/encrypt-share/' + token : '');
      if (!link) throw new Error('No share token returned');
      await navigator.clipboard.writeText(link);
      showToast('Encrypted share link copied', 'success');
    } catch (e) {
      showToast('Encrypted share failed: ' + e.message, 'error');
    }
  });

  // Fullscreen toggle
  const fullscreenBtn = document.getElementById('fullscreenBtn');
  if (fullscreenBtn) {
    fullscreenBtn.addEventListener('click', () => {
      document.body.classList.toggle('chat-fullscreen');
      fullscreenBtn.textContent = document.body.classList.contains('chat-fullscreen') ? '⛶' : '⛶';
      showToast(document.body.classList.contains('chat-fullscreen') ? 'Fullscreen mode' : 'Normal mode', 'info');
    });
  }

  // Copy code buttons (delegated)
  document.getElementById('messages').addEventListener('click', e => {
    const btn = e.target.closest('.copy-code-btn');
    if (!btn) return;
    const id = btn.dataset.id;
    const code = codeBlockMap.get(id);
    if (code) {
      navigator.clipboard.writeText(code).then(() => {
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = 'Copy', 1500);
      }).catch(() => {
        btn.textContent = 'Failed';
        setTimeout(() => btn.textContent = 'Copy', 1500);
      });
    }
  });

  // Message action buttons (delegated)
  document.getElementById('messages').addEventListener('click', e => {
    const btn = e.target.closest('.msg-action-btn');
    if (!btn) return;
    const action = btn.dataset.action;
    const msgEl = btn.closest('.message');
    if (!msgEl) return;
    const rawText = msgEl.dataset.rawText || '';

    if (action === 'copy') {
      navigator.clipboard.writeText(rawText).then(() => {
        showToast('Message copied', 'success');
      }).catch(() => showToast('Copy failed', 'error'));
    } else if (action === 'delete') {
      msgEl.remove();
      showToast('Message deleted', 'info');
    } else if (action === 'edit' && msgEl.classList.contains('user')) {
      const input = document.getElementById('input');
      if (input) {
        input.value = rawText;
        input.focus();
        msgEl.remove();
        showToast('Message loaded for editing', 'info');
      }
    } else if (action === 'regenerate' && msgEl.classList.contains('ai')) {
      msgEl.remove();
      showToast('Regenerating...', 'info');
      // Find the preceding user message
      const allMsgs = Array.from(document.querySelectorAll('.message'));
      const idx = allMsgs.indexOf(msgEl);
      const prevUser = allMsgs.slice(0, idx).reverse().find(m => m.classList.contains('user'));
      const input = document.getElementById('input');
      if (prevUser && input) {
        const raw = prevUser.dataset.rawText || prevUser.querySelector('.msg-body')?.textContent || '';
        if (raw.trim()) {
          input.value = raw.trim();
          sendChatStream();
        } else {
          showToast('No user message to regenerate from', 'error');
        }
      } else {
        showToast('No user message to regenerate from', 'error');
      }
    }
  });

  // Message reaction buttons (delegated)
  document.getElementById('messages').addEventListener('click', e => {
    const btn = e.target.closest('.msg-reaction-btn');
    if (!btn) return;
    const reaction = btn.dataset.reaction;
    const msgEl = btn.closest('.message');
    if (!msgEl) return;
    // Toggle: only one reaction active at a time per message
    msgEl.querySelectorAll('.msg-reaction-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    showToast(reaction === 'up' ? 'Thanks for the feedback!' : 'Thanks, we\'ll improve.', 'info');
  });

  // Auto-resize textarea
  const input = document.getElementById('input');
  if (input) {
    input.addEventListener('input', () => {
      input.style.height = 'auto';
      input.style.height = Math.min(input.scrollHeight, 200) + 'px';
    });
  }

  // Restore title and favicon when tab becomes visible
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
      document.title = aiName + ' — Secure AI Agent';
      unreadCount = 0;
      updateFaviconBadge(0);
    }
  });

  // Keyboard shortcuts
  document.addEventListener('keydown', e => {
    // Escape closes sidebar search first, then modals
    if (e.key === 'Escape') {
      if (sidebarSearchPanel?.classList.contains('open')) {
        e.stopPropagation();
        closeSidebarSearch();
        return;
      }
      document.querySelectorAll('.modal, .api-key-modal').forEach(m => m.style.display = 'none');
    }
    // Cmd/Ctrl + K → sidebar search
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      openSidebarSearch();
    }
    // Cmd/Ctrl + N → new chat
    if ((e.metaKey || e.ctrlKey) && e.key === 'n') {
      e.preventDefault();
      newChatBtn?.click();
    }
    // Cmd/Ctrl + , → settings
    if ((e.metaKey || e.ctrlKey) && e.key === ',') {
      e.preventDefault();
      openSettings();
    }
    // Cmd/Ctrl + Shift + P → theme picker
    if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === 'P') {
      e.preventDefault();
      showThemePicker();
    }
    // ? → keyboard shortcuts help (when not in input/textarea)
    const tag = e.target.tagName;
    const isTyping = tag === 'INPUT' || tag === 'TEXTAREA' || e.target.isContentEditable;
    if (e.key === '?' && !isTyping) {
      e.preventDefault();
      const modal = document.getElementById('shortcutsModal');
      if (modal) modal.style.display = 'flex';
    }
  });

  // Backend connection status indicator
  async function checkConnection() {
    const statusEl = document.getElementById('connectionStatus');
    if (!statusEl) return;
    try {
      const res = await fetch(API + '/api/status', { method: 'GET', signal: AbortSignal.timeout(5000) });
      if (res.ok) {
        statusEl.className = 'connection-status online';
        const label = statusEl.querySelector('.status-label');
        if (label) { label.dataset.i18n = 'online'; label.textContent = t('online'); }
        statusEl.title = 'Backend connected';
      } else {
        throw new Error('Status ' + res.status);
      }
    } catch (e) {
      statusEl.className = 'connection-status offline';
      const label = statusEl.querySelector('.status-label');
      if (label) { label.dataset.i18n = 'offlineStatus'; label.textContent = t('offlineStatus'); }
      statusEl.title = 'Backend unreachable — check if server is running';
    }
  }
  checkConnection();
  setInterval(checkConnection, 30000);

  // Drag & drop file upload
  const dragOverlay = document.getElementById('dragOverlay');
  ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(evt => {
    document.body.addEventListener(evt, e => {
      e.preventDefault();
      e.stopPropagation();
    });
  });
  document.body.addEventListener('dragenter', () => dragOverlay?.classList.add('visible'));
  document.body.addEventListener('dragleave', e => {
    if (e.relatedTarget === null) dragOverlay?.classList.remove('visible');
  });
  document.body.addEventListener('drop', async e => {
    dragOverlay?.classList.remove('visible');
    const files = e.dataTransfer?.files;
    if (files && files.length > 0) {
      for (const file of Array.from(files)) {
        addMessage('📎 Uploading **' + file.name + '**...', true);
        const data = await uploadFile(file);
        if (data) {
          addMessage('✅ Uploaded **' + file.name + '** — ' + data.mime_type + ' (' + (data.size / 1024).toFixed(1) + ' KB)', false);
        } else {
          addMessage('❌ Failed to upload **' + file.name + '**', false);
        }
      }
    }
  });

  // Stop generating button
  document.getElementById('stopBtn')?.addEventListener('click', () => {
    endStream();
    showTyping(false);
    showToast('Generation stopped', 'info');
  });

  // Prompt suggestions
  document.getElementById('messages').addEventListener('click', e => {
    const chip = e.target.closest('.prompt-chip');
    if (!chip) return;
    const input = document.getElementById('input');
    if (input) {
      input.value = chip.dataset.prompt;
      input.focus();
      input.dispatchEvent(new Event('input'));
    }
  });

  // Approval toast wiring
  const approvalToast = document.getElementById('approvalToast');
  const approvalToastBtn = document.getElementById('approvalToastBtn');
  const approvalToastDismiss = document.getElementById('approvalToastDismiss');
  let approvalToastTimeout = null;
  function hideApprovalToast() {
    if (approvalToast) approvalToast.style.display = 'none';
    if (approvalToastTimeout) clearTimeout(approvalToastTimeout);
    approvalToastTimeout = null;
  }
  function showApprovalToast() {
    if (approvalToast) approvalToast.style.display = 'flex';
    if (approvalToastTimeout) clearTimeout(approvalToastTimeout);
    approvalToastTimeout = setTimeout(hideApprovalToast, 10000);
  }
  if (approvalToastBtn) {
    approvalToastBtn.addEventListener('click', async () => {
      await switchTab('memory');
      hideApprovalToast();
    });
  }
  if (approvalToastDismiss) {
    approvalToastDismiss.addEventListener('click', hideApprovalToast);
  }

  // Poll memory queue for pending approvals
  async function checkMemoryQueue() {
    try {
      const res = await fetch(`${API}/api/memory/queue`);
      if (!res.ok) return;
      const data = await res.json();
      const pending = data.proposals || data.pending || data.queue || [];
      const queueBadge = document.getElementById('queueBadge');
      if (queueBadge) {
        queueBadge.textContent = pending.length;
        queueBadge.style.display = pending.length > 0 ? 'inline-flex' : 'none';
      }
      if (approvalToast) {
        if (pending.length > 0) showApprovalToast(); else hideApprovalToast();
      }
      const toastList = document.getElementById('approvalToastList');
      if (toastList) {
        toastList.innerHTML = pending.slice(0, 3).map(p => {
          const label = `${p.memory_type || 'memory'}: ${p.key || 'unknown'}`;
          return `<li>${escapeHtml(label)}${pending.length > 3 ? '...' : ''}</li>`;
        }).join('');
      }
    } catch (_) {
      // Backend may not support this endpoint
    }
  }
  checkMemoryQueue();
  setInterval(checkMemoryQueue, 30000);

  // Scheduled Tasks
  const taskHour = document.getElementById('taskHour');
  const taskMinute = document.getElementById('taskMinute');
  if (taskHour) for (let i = 0; i < 24; i++) taskHour.add(new Option(String(i).padStart(2, '0'), i));
  if (taskMinute) for (let i = 0; i < 60; i += 5) taskMinute.add(new Option(String(i).padStart(2, '0'), i));
  const taskFreq = document.getElementById('taskFreq');
  const taskDay = document.getElementById('taskDay');
  const taskCron = document.getElementById('taskCron');
  if (taskFreq) {
    taskFreq.addEventListener('change', () => {
      const freq = taskFreq.value;
      if (taskDay) taskDay.style.display = freq === 'weekly' ? 'inline' : 'none';
      if (taskCron) taskCron.style.display = freq === 'custom' ? 'inline' : 'none';
      if (taskHour) taskHour.style.display = freq === 'custom' ? 'none' : 'inline';
      if (taskMinute) taskMinute.style.display = freq === 'custom' ? 'none' : 'inline';
    });
  }
  function buildCron() {
    const freq = taskFreq?.value || 'daily';
    if (freq === 'custom') return taskCron?.value?.trim() || '';
    const h = taskHour?.value || '0';
    const m = taskMinute?.value || '0';
    if (freq === 'hourly') return `${m} * * * *`;
    if (freq === 'weekly') return `${m} ${h} * * ${taskDay?.value || '1'}`;
    return `${m} ${h} * * *`;
  }
  async function renderTasks() {
    const list = document.getElementById('taskList');
    if (!list) return;
    let tasks = [];
    try {
      const res = await fetch(`${API}/api/scheduled-tasks`);
      if (res.ok) tasks = await res.json();
    } catch (_) {}
    if (!tasks.length) {
      list.innerHTML = '<div style="padding:12px;color:var(--text-dim);font-size:0.85rem;">No scheduled tasks yet.</div>';
      return;
    }
    list.innerHTML = tasks.map(t => `
      <div class="task-item" style="display:flex;justify-content:space-between;align-items:center;padding:10px;border:1px solid var(--border);border-radius:8px;margin-bottom:8px;">
        <div>
          <div style="font-weight:500;">${escapeHtml(t.prompt)}</div>
          <div style="font-size:0.75rem;color:var(--text-dim);">${escapeHtml(t.cron)}</div>
        </div>
        <button class="btn btn-secondary task-delete-btn" data-id="${t.id}">Delete</button>
      </div>
    `).join('');
    list.querySelectorAll('.task-delete-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        try {
          const res = await fetch(`${API}/api/scheduled-tasks/${encodeURIComponent(btn.dataset.id)}`, {
            method: 'DELETE',
            headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {}
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          await renderTasks();
          showToast('Task deleted', 'success');
        } catch (e) {
          showToast('Failed to delete task: ' + e.message, 'error');
        }
      });
    });
  }
  document.getElementById('taskCreateBtn')?.addEventListener('click', async () => {
    const prompt = document.getElementById('taskPrompt')?.value.trim();
    const cron = buildCron();
    if (!prompt || !cron) {
      showToast('Enter a prompt and schedule', 'error');
      return;
    }
    try {
      const res = await fetch(`${API}/api/scheduled-tasks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) },
        body: JSON.stringify({ cron, prompt })
      });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      document.getElementById('taskPrompt').value = '';
      await renderTasks();
      showToast('Task scheduled', 'success');
    } catch (e) {
      showToast('Failed to schedule task: ' + e.message, 'error');
    }
  });
  renderTasks();

  // RAG settings (saved locally until backend RAG is wired)
  function getRagSettings() {
    return JSON.parse(localStorage.getItem('rag_settings') || '{}');
  }
  function saveRagSettings(s) {
    localStorage.setItem('rag_settings', JSON.stringify(s));
  }
  function renderRagDbs() {
    const s = getRagSettings();
    const select = document.getElementById('ragDbSelect');
    const path = document.getElementById('ragDbPath');
    if (!select) return;
    const dbs = s.databases || ['default'];
    const active = s.activeDatabase || 'default';
    select.innerHTML = dbs.map(db => `<option value="${db}" ${db === active ? 'selected' : ''}>${db}</option>`).join('');
    if (path) path.textContent = `~/.muccheai/rag/${active}/`;
  }
  function loadRagSettings() {
    const s = getRagSettings();
    const enabled = document.getElementById('ragEnabled');
    if (enabled) enabled.checked = s.enabled ?? false;
    const chunkSize = document.getElementById('ragChunkSize');
    if (chunkSize) chunkSize.value = s.chunkSize ?? 512;
    const overlap = document.getElementById('ragChunkOverlap');
    if (overlap) overlap.value = s.chunkOverlap ?? 64;
    const temp = document.getElementById('ragTemperature');
    if (temp) temp.value = s.temperature ?? 0.3;
    const semantic = document.getElementById('ragSemantic');
    if (semantic) semantic.checked = s.semantic ?? true;
    const model = document.getElementById('ragEmbeddingModel');
    if (model) model.value = s.embeddingModel ?? '';
    const provider = document.getElementById('ragEmbeddingProvider');
    if (provider) provider.value = s.embeddingProvider ?? 'ollama';
    const apiKey = document.getElementById('ragEmbeddingApiKey');
    if (apiKey) apiKey.value = s.embeddingApiKey ?? '';
    const apiBase = document.getElementById('ragEmbeddingApiBase');
    if (apiBase) apiBase.value = s.embeddingApiBase ?? '';
    const fallback = document.getElementById('ragKeywordFallback');
    if (fallback) fallback.checked = s.keywordFallback ?? true;
    renderRagDbs();
  }
  document.getElementById('ragDbSelect')?.addEventListener('change', () => {
    const s = getRagSettings();
    s.activeDatabase = document.getElementById('ragDbSelect')?.value || 'default';
    saveRagSettings(s);
    renderRagDbs();
  });
  document.getElementById('ragDbAddBtn')?.addEventListener('click', () => {
    const input = document.getElementById('ragDbNameInput');
    const name = input?.value.trim();
    if (!name) return;
    const s = getRagSettings();
    s.databases = s.databases || ['default'];
    if (!s.databases.includes(name)) s.databases.push(name);
    s.activeDatabase = name;
    saveRagSettings(s);
    renderRagDbs();
    if (input) input.value = '';
  });
  document.getElementById('ragDbRemoveBtn')?.addEventListener('click', () => {
    const s = getRagSettings();
    const active = s.activeDatabase || 'default';
    if (active === 'default') {
      showToast('Cannot remove the default database', 'warning');
      return;
    }
    if (!confirm(`Remove database "${active}"? Files on disk are not deleted.`)) return;
    s.databases = (s.databases || ['default']).filter(db => db !== active);
    s.activeDatabase = s.databases[0] || 'default';
    saveRagSettings(s);
    renderRagDbs();
  });
  async function scanRagFolder() {
    const s = getRagSettings();
    const active = s.activeDatabase || 'default';
    const list = document.getElementById('ragFileList');
    if (list) list.innerHTML = '<span style="color:var(--text-dim);">Scanning...</span>';
    try {
      const res = await fetch(`${API}/api/rag/${encodeURIComponent(active)}/files`);
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const data = await res.json();
      const files = data.files || [];
      if (list) {
        if (!files.length) {
          list.innerHTML = '<span style="color:var(--text-dim);">No files in folder. Drop documents into:<br><code>' + escapeHtml(data.path || '') + '</code></span>';
        } else {
          list.innerHTML = '<ul style="margin:0;padding-left:18px;">' + files.map(f =>
            `<li>${escapeHtml(f.name)} <span style="color:var(--text-dim);">(${(f.size / 1024).toFixed(1)} KB)</span></li>`
          ).join('') + '</ul>';
        }
      }
    } catch (e) {
      if (list) list.innerHTML = '<span style="color:#ff6b6b;">Failed to scan: ' + escapeHtml(e.message) + '</span>';
    }
  }
  document.getElementById('ragScanBtn')?.addEventListener('click', scanRagFolder);
  document.getElementById('ragDbSelect')?.addEventListener('change', () => {
    const list = document.getElementById('ragFileList');
    if (list) list.innerHTML = '';
  });
  document.getElementById('ragSaveBtn')?.addEventListener('click', () => {
    const s = getRagSettings();
    s.enabled = document.getElementById('ragEnabled')?.checked ?? false;
    s.chunkSize = parseInt(document.getElementById('ragChunkSize')?.value || '512', 10);
    s.chunkOverlap = parseInt(document.getElementById('ragChunkOverlap')?.value || '64', 10);
    s.temperature = parseFloat(document.getElementById('ragTemperature')?.value || '0.3');
    s.semantic = document.getElementById('ragSemantic')?.checked ?? true;
    s.embeddingModel = document.getElementById('ragEmbeddingModel')?.value || '';
    s.embeddingProvider = document.getElementById('ragEmbeddingProvider')?.value || 'ollama';
    s.embeddingApiKey = document.getElementById('ragEmbeddingApiKey')?.value || '';
    s.embeddingApiBase = document.getElementById('ragEmbeddingApiBase')?.value || '';
    s.keywordFallback = document.getElementById('ragKeywordFallback')?.checked ?? true;
    s.databases = s.databases || ['default'];
    s.activeDatabase = s.activeDatabase || 'default';
    saveRagSettings(s);
    showToast('RAG settings saved', 'success');
  });
  loadRagSettings();

  // Custom Tools
  async function renderTools() {
    const list = document.getElementById('toolList');
    if (!list) return;
    let tools = [];
    try {
      const res = await fetch(`${API}/api/custom-tools`);
      if (res.ok) {
        const data = await res.json();
        tools = data.tools || [];
      }
    } catch (_) {}
    if (!tools.length) {
      list.innerHTML = '<div style="padding:12px;color:var(--text-dim);font-size:0.85rem;">No custom tools yet.</div>';
      return;
    }
    list.innerHTML = tools.map(t => `
      <div class="tool-item" style="display:flex;justify-content:space-between;align-items:center;padding:10px;border:1px solid var(--border);border-radius:8px;margin-bottom:8px;">
        <div>
          <div style="font-weight:500;">${escapeHtml(t.name)}</div>
          <div style="font-size:0.75rem;color:var(--text-dim);">${escapeHtml(t.method)} ${escapeHtml(t.url_template)}</div>
        </div>
        <button class="btn btn-secondary tool-delete-btn" data-name="${t.name}">Delete</button>
      </div>
    `).join('');
    list.querySelectorAll('.tool-delete-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        try {
          const res = await fetch(`${API}/api/custom-tools/${encodeURIComponent(btn.dataset.name)}`, {
            method: 'DELETE',
            headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {}
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          await renderTools();
          showToast('Tool deleted', 'success');
        } catch (e) {
          showToast('Failed to delete tool: ' + e.message, 'error');
        }
      });
    });
  }
  document.getElementById('toolCreateBtn')?.addEventListener('click', async () => {
    const name = document.getElementById('toolName')?.value.trim();
    const method = document.getElementById('toolMethod')?.value;
    const url = document.getElementById('toolUrl')?.value.trim();
    if (!name || !url) {
      showToast('Enter tool name and URL', 'error');
      return;
    }
    try {
      const res = await fetch(`${API}/api/custom-tools`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) },
        body: JSON.stringify({ name, method, url_template: url })
      });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      document.getElementById('toolName').value = '';
      document.getElementById('toolUrl').value = '';
      await renderTools();
      showToast('Tool created', 'success');
    } catch (e) {
      showToast('Failed to create tool: ' + e.message, 'error');
    }
  });
  renderTools();

  // Hide splash screen after a brief delay so fonts/styles settle
  setTimeout(() => {
    const splash = document.getElementById('splashScreen');
    if (splash) splash.classList.add('hidden');
  }, 600);
});
