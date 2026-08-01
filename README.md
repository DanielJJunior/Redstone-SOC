# ⛏️ Redstone SOC

> 🇧🇷 Português abaixo • 🇺🇸 English below

---

# 🇧🇷 Português

## 🛡️ Redstone SOC

O **Redstone SOC** é um projeto pessoal desenvolvido em Python, inspirado no universo de **Minecraft**, criado com o objetivo de praticar e demonstrar conhecimentos em **Segurança da Informação**, **Blue Team**, **Security Operations Center (SOC)** e **Detection Engineering**.

O projeto monitora diretórios em tempo real, identifica arquivos potencialmente maliciosos utilizando técnicas de Threat Intelligence, calcula hashes SHA-256, gera alertas estruturados em JSON e apresenta todas as informações em um Dashboard desenvolvido com Streamlit.

Todo o projeto foi desenvolvido utilizando apenas tecnologias gratuitas, com foco em aprendizado, organização de código e demonstração prática de conceitos utilizados em SOCs modernos.

---

# 🎯 Objetivos

- Praticar conceitos de Blue Team e SOC.
- Desenvolver habilidades em Python aplicadas à Segurança da Informação.
- Demonstrar conhecimentos em Detection Engineering.
- Construir um projeto autoral para portfólio.
- Evoluir continuamente o projeto com novas funcionalidades.

---

# ✨ Funcionalidades

- ✅ Monitoramento de diretórios em tempo real
- ✅ Observer baseado em Watchdog
- ✅ Análise automática de arquivos
- ✅ Cálculo de Hash SHA-256
- ✅ Detecção por Nome do Arquivo
- ✅ Detecção por Hash
- ✅ Detecção por Extensão
- ✅ Threat Intelligence desacoplada
- ✅ Base de IOCs em JSON
- ✅ Mapeamento MITRE ATT&CK
- ✅ Recomendações de resposta ao incidente
- ✅ Geração automática de Alertas JSON
- ✅ Histórico de Alertas
- ✅ Dashboard em Streamlit
- ✅ Busca de Alertas
- ✅ Timeline de Eventos
- ✅ Métricas por Severidade
- ✅ Visualização detalhada de Alertas

---

# 🖥️ Dashboard

O Dashboard permite visualizar rapidamente todas as detecções realizadas pelo Redstone SOC.

Atualmente possui:

- Dashboard em tempo real
- Métricas de severidade
- Lista de alertas
- Busca por arquivo
- Timeline de eventos
- Detalhes completos do alerta
- MITRE ATT&CK
- Recommendation

---

# 📁 Estrutura do Projeto

```text
Redstone-SOC
│
├── alerts/
├── config/
├── dashboard/
├── samples/
├── src/
│   ├── alert_engine.py
│   ├── detection_engine.py
│   ├── file_analyzer.py
│   ├── hash_engine.py
│   ├── observer.py
│   ├── threat_intelligence.py
│   └── utils.py
│
├── main.py
├── requirements.txt
└── README.md
```

---

# 🎮 Por que Minecraft?

O projeto utiliza uma identidade visual inspirada em Minecraft para tornar o aprendizado mais divertido.

Alguns elementos utilizados:

- ⛏️ Redstone SOC
- 👀 Observer Block
- ⚡ Redstone Signals
- 🚨 Creeper Alerts (planejado)

Assim como a Redstone automatiza mecanismos dentro do Minecraft, o Redstone SOC automatiza tarefas comuns de um Security Operations Center.

---

# 🚀 Como executar

## Clone o projeto

```bash
git clone https://github.com/DanielJJunior/Redstone-SOC.git
cd Redstone-SOC
```

---

## Crie um ambiente virtual

Windows

```bash
python -m venv .venv
```

Linux

```bash
python3 -m venv .venv
```

---

## Ative o ambiente

Windows

```bash
.venv\Scripts\activate
```

Linux

```bash
source .venv/bin/activate
```

---

## Instale as dependências

```bash
pip install -r requirements.txt
```

---

## Execute o monitor

```bash
python main.py
```

---

## Execute o Dashboard

```bash
streamlit run dashboard/app.py
```

---

# 📌 Roadmap

## v1.0

- ✅ Monitoramento em tempo real
- ✅ Hash SHA256
- ✅ IOC Detection
- ✅ Dashboard
- ✅ MITRE
- ✅ Recommendations

## Próximas versões

- 🎯 Threat Score
- 📊 Dashboard com Plotly
- 🦠 IOC Database expandida
- 📄 Exportação de relatórios
- 💬 Discord Webhook
- 🌐 Integração opcional com VirusTotal
- 📈 Estatísticas avançadas
- 🎮 Mais elementos inspirados em Minecraft

---

# 🛠️ Tecnologias

- Python
- Streamlit
- Watchdog
- JSON
- Hashlib
- Plotly (em evolução)

---

# 📚 Conceitos abordados

- Security Operations Center (SOC)
- Blue Team
- Detection Engineering
- Threat Intelligence
- File Integrity Monitoring
- SHA-256 Hashing
- Indicators of Compromise (IOCs)
- MITRE ATT&CK
- Python Automation

---

# 🤝 Contribuições

Sugestões, melhorias e feedbacks são sempre bem-vindos.

Caso tenha alguma ideia para evoluir o Redstone SOC, fique à vontade para abrir uma Issue ou Pull Request.

---

# 📄 Licença

Este projeto está licenciado sob a licença MIT.

---

# 🇺🇸 English

## 🛡️ Redstone SOC

Redstone SOC is a lightweight, Minecraft-inspired Security Operations Center built in Python.

The project was created to practice and demonstrate hands-on skills in Security Operations, Blue Team activities and Detection Engineering.

It monitors directories in real time, analyzes files, calculates SHA-256 hashes, searches a Threat Intelligence database, detects Indicators of Compromise (IOCs), generates structured JSON alerts and displays all collected information through a Streamlit Dashboard.

The entire project was designed using only free technologies with a strong focus on clean architecture, modularity and learning.

---

# 🎯 Goals

- Practice Blue Team concepts
- Learn Detection Engineering
- Build a practical Python security project
- Create a portfolio project
- Continuously improve with new features

---

# ✨ Current Features

- ✅ Real-time directory monitoring
- ✅ Watchdog Observer
- ✅ Automatic file analysis
- ✅ SHA-256 hashing
- ✅ Filename IOC detection
- ✅ Hash IOC detection
- ✅ Executable extension detection
- ✅ Threat Intelligence database
- ✅ Decoupled IOC store
- ✅ MITRE ATT&CK mapping
- ✅ Incident response recommendations
- ✅ JSON alert generation
- ✅ Alert history
- ✅ Streamlit Dashboard
- ✅ Search alerts
- ✅ Timeline
- ✅ Severity metrics
- ✅ Threat details visualization

---

# 🚀 Getting Started

Clone the repository

```bash
git clone https://github.com/DanielJJunior/Redstone-SOC.git
cd Redstone-SOC
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run the monitor

```bash
python main.py
```

Run the dashboard

```bash
streamlit run dashboard/app.py
```

---

# 🛠️ Tech Stack

- Python
- Streamlit
- Watchdog
- JSON
- Hashlib
- Plotly (planned)

---

# 📚 Concepts Covered

- Security Operations Center
- Blue Team
- Detection Engineering
- Threat Intelligence
- File Integrity Monitoring
- SHA-256 Hashing
- MITRE ATT&CK
- Indicators of Compromise (IOCs)

---

# 📌 Roadmap

Upcoming features include:

- Threat Score
- Plotly Dashboard
- IOC Database Expansion
- Discord Webhook
- VirusTotal Integration
- Report Export
- Advanced Statistics

---

# 📄 License

Licensed under the MIT License.