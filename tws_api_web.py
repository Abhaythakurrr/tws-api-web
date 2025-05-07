import logging
import json
from flask import Flask, request, render_template_string, session, redirect, url_for
from tws_api_client3 import TWSApiClient, validate_engine, validate_prompt_name, REQUESTS_AVAILABLE, GREEN, RESET, generate_ascii_art

# Flask app setup
app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Replace with a secure key

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format=f'{GREEN}%(asctime)s - %(levelname)s - %(message)s{RESET}',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Simulated master engines
masters = ["BAP051", "BAP052", "PROD01"]

# HTML template with Tailwind CSS, Inter font, and enhanced UX
TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ABHII TWS API Client</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', Arial, sans-serif; }
        .sidebar { transition: transform 0.3s ease; }
        .card { transition: transform 0.2s; }
        .card:hover { transform: translateY(-2px); }
        .btn { transition: all 0.2s; }
        .btn:hover { transform: scale(1.05); }
        .toast { transition: opacity 0.5s; }
        @media (max-width: 768px) {
            .sidebar { transform: translateX(-100%); }
            .sidebar.open { transform: translateX(0); }
        }
        pre { white-space: pre-wrap; word-wrap: break-word; }
    </style>
</head>
<body class="bg-blue-950 text-white">
    <!-- Sidebar -->
    <div class="sidebar fixed inset-y-0 left-0 w-64 bg-gray-900 p-4 overflow-y-auto md:transform-none z-50">
        <div class="flex items-center justify-between mb-6">
            <h2 class="text-xl font-bold text-green-400">ABHII TWS</h2>
            <button id="close-sidebar" class="md:hidden text-white text-xl">✕</button>
        </div>
        <nav>
            <a href="{{ url_for('index') }}" class="flex items-center py-2 px-4 rounded hover:bg-gray-800 {% if request.path == url_for('index') %}bg-gray-800{% endif %}">
                <span class="mr-2">🏠</span> Home
            </a>
            {% if session.get('initialized') %}
                <a href="{{ url_for('get_prompt') }}" class="flex items-center py-2 px-4 rounded hover:bg-gray-800 {% if request.path == url_for('get_prompt') %}bg-gray-800{% endif %}">
                    <span class="mr-2">📋</span> Get Prompt
                </a>
                <!-- Add more operations here (e.g., Create Job) -->
            {% endif %}
        </nav>
    </div>

    <!-- Main Content -->
    <div class="md:ml-64 p-6 min-h-screen">
        <header class="flex items-center justify-between mb-8">
            <div>
                <pre class="text-green-400 text-sm">{{ ascii_art }}</pre>
                <h1 class="text-3xl font-bold">TWS API Client</h1>
                {% if session.get('initialized') %}
                    <p class="text-gray-400 text-sm">Connected to {{ session.client_config.base_url }}</p>
                {% endif %}
            </div>
            <button id="open-sidebar" class="md:hidden text-white text-2xl">☰</button>
        </header>

        <!-- Messages -->
        {% if message %}
            <div id="toast" class="toast fixed top-4 right-4 bg-green-500 text-white p-4 rounded-lg shadow-xl opacity-100 max-w-sm">
                {{ message }}
            </div>
        {% endif %}
        {% if error %}
            <div id="toast" class="toast fixed top-4 right-4 bg-red-500 text-white p-4 rounded-lg shadow-xl opacity-100 max-w-sm">
                {{ error }}
            </div>
        {% endif %}

        <!-- Content -->
        <div class="max-w-3xl mx-auto">
            {% if not session.get('initialized') %}
                <div class="card bg-gray-900 p-6 rounded-xl shadow-lg">
                    <h2 class="text-2xl font-semibold mb-6 text-green-400">Initialize Client</h2>
                    <form method="POST" action="{{ url_for('initialize') }}" id="init-form">
                        <div class="mb-5">
                            <label class="block text-sm font-medium mb-2" for="base_url">API Base URL</label>
                            <input type="url" id="base_url" name="base_url" class="w-full p-3 rounded-lg bg-gray-800 text-white border border-gray-700 focus:outline-none focus:border-green-400" placeholder="https://tws.abhii.com:9443/twsd" required title="Enter the TWS API base URL">
                        </div>
                        <div class="mb-5">
                            <label class="block text-sm font-medium mb-2" for="username">Username</label>
                            <input type="text" id="username" name="username" class="w-full p-3 rounded-lg bg-gray-800 text-white border border-gray-700 focus:outline-none focus:border-green-400" required title="Enter your TWS username">
                        </div>
                        <div class="mb-5">
                            <label class="block text-sm font-medium mb-2" for="password">Password</label>
                            <input type="password" id="password" name="password" class="w-full p-3 rounded-lg bg-gray-800 text-white border border-gray-700 focus:outline-none focus:border-green-400" required title="Enter your TWS password">
                        </div>
                        <button type="submit" class="btn w-full bg-green-500 text-white p-3 rounded-lg hover:bg-green-600">Initialize</button>
                    </form>
                </div>
            {% else %}
                {% if operation == 'get_prompt' %}
                    <div class="card bg-gray-900 p-6 rounded-xl shadow-lg">
                        <h2 class="text-2xl font-semibold mb-6 text-green-400">Get Prompt</h2>
                        <form method="POST" action="{{ url_for('get_prompt') }}" id="get-prompt-form">
                            <div class="mb-5">
                                <label class="block text-sm font-medium mb-2" for="engine">Target Engine</label>
                                <select id="engine" name="engine" class="w-full p-3 rounded-lg bg-gray-800 text-white border border-gray-700 focus:outline-none focus:border-green-400" required title="Select the target engine">
                                    {% for master in masters %}
                                        <option value="{{ master }}">{{ master }}</option>
                                    {% endfor %}
                                </select>
                            </div>
                            <div class="mb-5">
                                <label class="block text-sm font-medium mb-2" for="prompt_name">Prompt Name</label>
                                <input type="text" id="prompt_name" name="prompt_name" class="w-full p-3 rounded-lg bg-gray-800 text-white border border-gray-700 focus:outline-none focus:border-green-400" required pattern="[a-zA-Z0-9]{1,40}" title="Alphanumeric, max 40 characters">
                            </div>
                            <button type="submit" class="btn w-full bg-green-500 text-white p-3 rounded-lg hover:bg-green-600">Retrieve Prompt</button>
                        </form>
                        {% if result %}
                            <div class="mt-6">
                                <h3 class="text-lg font-semibold mb-3 text-green-400">Result</h3>
                                <pre class="bg-gray-800 p-4 rounded-lg text-sm text-gray-200">{{ result }}</pre>
                            </div>
                        {% endif %}
                    </div>
                {% else %}
                    <div class="card bg-gray-900 p-6 rounded-xl shadow-lg">
                        <h2 class="text-2xl font-semibold mb-6 text-green-400">Welcome</h2>
                        <p class="text-gray-300">Select an operation from the sidebar to get started.</p>
                    </div>
                {% endif %}
            {% endif %}
        </div>
    </div>

    <!-- Footer -->
    <footer class="bg-gray-900 p-4 text-center text-gray-400 mt-8">
        <p>ABHII TWS API Client v1.0 | Powered by PrabhAI</p>
        
    </footer>

    <!-- JavaScript -->
    <script>
        // Sidebar toggle
        const openSidebar = document.getElementById('open-sidebar');
        const closeSidebar = document.getElementById('close-sidebar');
        const sidebar = document.querySelector('.sidebar');

        openSidebar?.addEventListener('click', () => {
            sidebar.classList.add('open');
        });

        closeSidebar?.addEventListener('click', () => {
            sidebar.classList.remove('open');
        });

        // Toast auto-hide
        const toast = document.getElementById('toast');
        if (toast) {
            setTimeout(() => {
                toast.style.opacity = '0';
                setTimeout(() => toast.remove(), 500);
            }, 3000);
        }

        // Form validation
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            form.addEventListener('submit', (e) => {
                const inputs = form.querySelectorAll('input[required], select[required]');
                let valid = true;
                inputs.forEach(input => {
                    if (!input.value.trim()) {
                        valid = false;
                        input.classList.add('border-red-500');
                        input.classList.remove('border-green-400');
                    } else {
                        input.classList.remove('border-red-500');
                        input.classList.add('border-green-400');
                    }
                });
                if (!valid) {
                    e.preventDefault();
                    const toast = document.createElement('div');
                    toast.id = 'toast';
                    toast.className = 'toast fixed top-4 right-4 bg-red-500 text-white p-4 rounded-lg shadow-xl opacity-100 max-w-sm';
                    toast.textContent = 'Please fill all required fields.';
                    document.body.appendChild(toast);
                    setTimeout(() => {
                        toast.style.opacity = '0';
                        setTimeout(() => toast.remove(), 500);
                    }, 3000);
                }
            });
        });

        // Input validation feedback
        const promptName = document.getElementById('prompt_name');
        if (promptName) {
            promptName.addEventListener('input', () => {
                const pattern = /^[a-zA-Z0-9]{1,40}$/;
                if (pattern.test(promptName.value)) {
                    promptName.classList.add('border-green-400');
                    promptName.classList.remove('border-red-500');
                } else {
                    promptName.classList.add('border-red-500');
                    promptName.classList.remove('border-green-400');
                }
            });
        }
    </script>
</body>
</html>
"""

# Routes
@app.route('/', methods=['GET'])
def index():
    session.pop('message', None)
    session.pop('error', None)
    return render_template_string(TEMPLATE, ascii_art=generate_ascii_art(), masters=masters)

@app.route('/initialize', methods=['POST'])
def initialize():
    base_url = request.form.get('base_url')
    username = request.form.get('username')
    password = request.form.get('password')

    if not base_url or not username or not password:
        session['error'] = "All fields are required."
        return redirect(url_for('index'))

    try:
        client = TWSApiClient(base_url, username, password, "", proxies=None, verify_ssl=True)
        if client.test_connectivity():
            session['client_config'] = {'base_url': base_url, 'username': username, 'password': password}
            session['initialized'] = True
            session['message'] = "Connection successful. Select an operation."
        else:
            session['error'] = "Connection test failed. Check URL, credentials, or network."
    except Exception as e:
        session['error'] = f"Failed to initialize client: {str(e)}"

    return redirect(url_for('index'))

@app.route('/get_prompt', methods=['GET', 'POST'])
def get_prompt():
    if not session.get('initialized'):
        session['error'] = "Client not initialized. Please initialize first."
        return redirect(url_for('index'))

    if request.method == 'GET':
        return render_template_string(TEMPLATE, operation='get_prompt', masters=masters)

    engine = request.form.get('engine', '').strip().upper()
    prompt_name = request.form.get('prompt_name', '').strip()

    if not validate_engine(engine, masters):
        session['error'] = f"Invalid engine: {engine}. Must be one of {', '.join(masters)}."
        return redirect(url_for('get_prompt'))
    if not validate_prompt_name(prompt_name):
        session['error'] = "Invalid prompt name. Alphanumeric, max 40 chars."
        return redirect(url_for('get_prompt'))

    client_config = session['client_config']
    client = TWSApiClient(
        client_config['base_url'],
        client_config['username'],
        client_config['password'],
        engine,
        proxies=None,
        verify_ssl=True
    )

    try:
        prompt = client.get_prompt(prompt_name)
        result = json.dumps(prompt, indent=2)
        return render_template_string(TEMPLATE, operation='get_prompt', masters=masters, message="Prompt retrieved successfully.", result=result)
    except Exception as e:
        session['error'] = f"Failed to retrieve prompt: {str(e)}"
        return redirect(url_for('get_prompt'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)