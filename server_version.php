<?php
session_start();
date_default_timezone_set('UTC'); 

// --- CONFIGURATION ---
$ACCESS_PASSWORD = 'password';     // <--- CHANGE THIS. Password should be renamed to what you want YOUR password to be
$MAX_ATTEMPTS    = 3;              
$BLACKLIST_FILE  = 'blacklist.txt';
$ATTEMPT_FILE    = 'login_attempts.json';
// ---------------------

// 1. GET USER IP
$userIP = $_SERVER['REMOTE_ADDR'];

// 2. CHECK IF IP IS BANNED
if (file_exists($BLACKLIST_FILE)) {
    // Use @ to suppress warnings if file is locked/unreadable
    $banned_ips = @file($BLACKLIST_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($banned_ips && in_array($userIP, $banned_ips)) {
        header('HTTP/1.1 403 Forbidden');
        die("<h1 style='font-family:sans-serif;text-align:center;margin-top:50px;'>403 Forbidden</h1><p style='font-family:sans-serif;text-align:center;'>Access denied due to excessive login failures.</p>");
    }
}

// 3. HANDLE LOGOUT
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// 4. HANDLE LOGIN ATTEMPT
$loginError = '';
if (isset($_POST['login_attempt'])) {
    
    $attempts_data = file_exists($ATTEMPT_FILE) ? json_decode(@file_get_contents($ATTEMPT_FILE), true) : [];
    if (!is_array($attempts_data)) $attempts_data = [];
    
    $current_fails = isset($attempts_data[$userIP]) ? $attempts_data[$userIP] : 0;

    if ($_POST['password'] === $ACCESS_PASSWORD) {
        // SUCCESS
        if (isset($attempts_data[$userIP])) {
            unset($attempts_data[$userIP]);
            @file_put_contents($ATTEMPT_FILE, json_encode($attempts_data));
        }
        $_SESSION['is_logged_in'] = true;
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    } else {
        // FAILURE
        $current_fails++;
        $attempts_data[$userIP] = $current_fails;
        @file_put_contents($ATTEMPT_FILE, json_encode($attempts_data));

        if ($current_fails >= $MAX_ATTEMPTS) {
            @file_put_contents($BLACKLIST_FILE, $userIP . PHP_EOL, FILE_APPEND);
            unset($attempts_data[$userIP]);
            @file_put_contents($ATTEMPT_FILE, json_encode($attempts_data));
            die("<h1 style='font-family:sans-serif;text-align:center;margin-top:50px;'>403 Forbidden</h1><p style='font-family:sans-serif;text-align:center;'>Maximum login attempts exceeded. Your IP has been banned.</p>");
        } else {
            $remaining = $MAX_ATTEMPTS - $current_fails;
            $loginError = "Incorrect password. " . $remaining . " attempts remaining.";
        }
    }
}

// 5. CHECK AUTHENTICATION
if (!isset($_SESSION['is_logged_in']) || $_SESSION['is_logged_in'] !== true) {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Restricted Access</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f2f2f7; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; color: #1d1d1f; }
            .login-card { background: white; padding: 2.5rem; border-radius: 18px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 100%; max-width: 400px; text-align: center; }
            h1 { font-size: 1.5rem; margin-bottom: 1.5rem; }
            input { width: 100%; padding: 12px; margin-bottom: 15px; border: 1px solid #d2d2d7; border-radius: 10px; font-size: 1rem; }
            button { background: #007aff; color: white; border: none; padding: 12px; width: 100%; border-radius: 10px; font-size: 1rem; font-weight: 600; cursor: pointer; }
            button:hover { background: #0066cc; }
            .error { color: #ff3b30; margin-bottom: 15px; font-size: 0.9rem; line-height: 1.4; }
        </style>
    </head>
    <body>
        <div class="login-card">
            <h1>Field Report Generator</h1>
            <?php if($loginError): ?><div class="error"><?php echo $loginError; ?></div><?php endif; ?>
            <form method="post">
                <input type="hidden" name="login_attempt" value="1">
                <input type="password" name="password" placeholder="Enter Password" required autofocus>
                <button type="submit">Access System</button>
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// --- API ENDPOINT FOR SAVING (POST ONLY) ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Clean output buffer to ensure valid JSON
    ob_clean(); 
    header('Content-Type: application/json');
    error_reporting(0); // Disable warnings in JSON response

    $input = json_decode(file_get_contents('php://input'), true);
    
    if (isset($input['html']) && isset($input['type'])) {
        $htmlContent = $input['html'];
        // Sanitize filename
        $reportType = preg_replace('/[^a-zA-Z0-9]/', '', $input['type']);
        // Sanitize HTML (prevent script injection)
        $htmlContent = preg_replace('#<script(.*?)>(.*?)</script>#is', '', $htmlContent);
        
        $filename = $reportType . '_' . date('Y-m-d_His') . '.html';
        
        if (file_put_contents($filename, $htmlContent)) {
            echo json_encode(['success' => true, 'url' => $filename]);
        } else {
            http_response_code(500);
            echo json_encode(['success' => false, 'error' => 'Write permission denied']);
        }
    } else {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Invalid input data']);
    }
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tactical Report Generator</title>
    <style>
        /* --- CORE STYLES --- */
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: #f2f2f7;
            color: #1d1d1f;
            min-height: 100vh;
            padding: 1rem;
        }
        .container { max-width: 700px; margin: 0 auto; padding-bottom: 4rem; position: relative; }
        
        /* LOGOUT LINK */
        .logout-link { position: absolute; top: 1rem; right: 0; color: #ff3b30; text-decoration: none; font-size: 0.9rem; font-weight: 600; }

        /* HEADER */
        header { text-align: center; padding: 2rem 1rem; }
        h1 { font-size: 2.2rem; font-weight: 700; letter-spacing: -0.02em; color: #000; }
        .subtitle { color: #6e6e73; font-size: 1.1rem; margin-top: 0.5rem; }

        /* SELECTION SCREEN GRID */
        #selection-screen { display: block; animation: fadeIn 0.4s ease; }
        .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1rem; margin-top: 1.5rem; }
        
        .card {
            background: white; border-radius: 16px; padding: 1.5rem;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05); cursor: pointer;
            transition: all 0.2s ease; border: 2px solid transparent;
        }
        .card:hover { transform: translateY(-3px); box-shadow: 0 5px 12px rgba(0,0,0,0.1); border-color: #007aff; }
        .card h3 { font-size: 1.2rem; margin-bottom: 0.5rem; color: #007aff; }
        .card p { font-size: 0.9rem; color: #666; line-height: 1.4; }

        /* WIZARD STEPS */
        #wizard-container { display: none; }
        
        .step {
            background: white; border-radius: 18px; padding: 1.5rem; margin-bottom: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.08); display: none;
        }
        .step.active { display: block; animation: slideUp 0.3s ease; }
        
        @keyframes slideUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

        label { display: block; font-size: 1.2rem; font-weight: 700; margin-bottom: 0.3rem; color: #000; }
        .helper-text { font-size: 0.95rem; color: #666; margin-bottom: 1rem; line-height: 1.4; }
        
        textarea {
            width: 100%; min-height: 110px; padding: 0.9rem;
            border: 1px solid #d2d2d7; border-radius: 10px; font-size: 1rem; font-family: inherit;
            resize: vertical; background: #fff; transition: border-color 0.2s, box-shadow 0.2s;
        }
        textarea:focus { outline: none; border-color: #007aff; box-shadow: 0 0 0 3px rgba(0,122,255,0.15); }

        .navigation { display: flex; justify-content: space-between; margin-top: 1.5rem; gap: 1rem; }

        /* BUTTONS */
        button {
            background: #007aff; color: white; border: none; padding: 1.1rem 1.5rem;
            font-size: 1.05rem; font-weight: 600; border-radius: 12px; cursor: pointer;
            transition: all 0.2s; flex: 1;
        }
        button.secondary { background: #e5e5ea; color: #000; }
        button:hover { background: #0066cc; }
        button.secondary:hover { background: #d1d1d6; }
        button:disabled { background: #ccc; cursor: not-allowed; }

        /* RED SERVER BUTTON */
        button.server-btn { background: #ff3b30; }
        button.server-btn:hover { background: #d63026; }

        /* PROGRESS BAR */
        .progress { height: 6px; background: #e5e5ea; border-radius: 3px; overflow: hidden; margin: 1.5rem 0; }
        .progress-fill { height: 100%; background: #007aff; width: 0%; transition: width 0.4s ease; }

        /* VERIFY & PREVIEW */
        #verify, #preview {
            background: white; border-radius: 18px; padding: 2rem 1.5rem;
            margin-top: 2rem; display: none; box-shadow: 0 1px 3px rgba(0,0,0,0.08);
        }
        
        h2 { font-size: 1.6rem; margin-bottom: 1.5rem; color: #000; border-bottom: 1px solid #e5e5ea; padding-bottom: 1rem; }
        
        .verify-item, .preview-item { margin-bottom: 1.5rem; }
        .verify-item strong, .preview-item strong { display: block; font-size: 0.9rem; text-transform: uppercase; color: #6e6e73; margin-bottom: 0.4rem; letter-spacing: 0.5px; }
        .preview-item p { color: #1d1d1f; line-height: 1.5; white-space: pre-wrap; font-size: 1.1rem; }

        .actions { display: flex; flex-wrap: wrap; gap: 1rem; margin-top: 2rem; }
        #copyFeedback { width: 100%; text-align: center; color: #34c759; font-weight: 600; margin-top: 10px; display: none; }
        
        /* SERVER FEEDBACK */
        #serverFeedback { 
            display: none; margin-top: 15px; padding: 15px; background: #e8f5e9; 
            border: 1px solid #4caf50; border-radius: 12px; color: #2e7d32; text-align: center; 
        }
        #serverFeedback a { color: #1b5e20; font-weight: bold; text-decoration: underline; }

        /* PRINT STYLING */
        @media print {
            body { background: white; padding: 0; margin: 0; }
            header, #selection-screen, .progress, .step, .navigation, #verify, .actions, #copyFeedback, button, #serverFeedback, .logout-link { display: none !important; }
            .container { max-width: 100%; margin: 0; padding: 0; visibility: visible; }
            #wizard-container { display: block !important; visibility: visible; }
            #preview { display: block !important; visibility: visible; box-shadow: none; padding: 0; margin: 0; width: 100%; }
            h2 { font-size: 24px; border-bottom: 2px solid #000; margin-bottom: 20px; }
            .preview-item p { font-size: 12pt; color: #000; }
            .preview-item strong { color: #000; font-weight: bold; }
        }
    </style>
</head>
<body>

<div class="container">
    <a href="?logout=true" class="logout-link">Logout</a>

    <!-- HEADER -->
    <header id="main-header">
        <h1 id="app-title">Field Report Generator</h1>
        <div class="subtitle" id="app-subtitle">Select a report type to begin</div>
    </header>

    <!-- SELECTION SCREEN -->
    <div id="selection-screen">
        <div class="grid">
            <div class="card" onclick="window.startReport('SALT')">
                <h3>SALT</h3>
                <p><strong>Brief Observation.</strong> Size, Activity, Location, Time.</p>
            </div>
            <div class="card" onclick="window.startReport('SALUTE')">
                <h3>SALUTE</h3>
                <p><strong>Standard Enemy Report.</strong> Size, Activity, Location, Unit, Time, Equipment.</p>
            </div>
            <div class="card" onclick="window.startReport('SITREP')">
                <h3>SITREP</h3>
                <p><strong>Situation Status.</strong> Enemy, Friendly, Logistics, & Command updates.</p>
            </div>
            <div class="card" onclick="window.startReport('INTREP')">
                <h3>INTREP</h3>
                <p><strong>Intelligence Event.</strong> Specific event details, source, and assessment.</p>
            </div>
            <div class="card" onclick="window.startReport('TACTREP')">
                <h3>TACTREP</h3>
                <p><strong>Tactical Event.</strong> Broad tactical update: Time, Area, Event, Actions.</p>
            </div>
            <div class="card" onclick="window.startReport('TACELINT')">
                <h3>TACELINT</h3>
                <p><strong>Electronic Signal.</strong> Frequency, Call Sign, Modulation, Location.</p>
            </div>
        </div>
    </div>

    <!-- WIZARD CONTAINER (Generated Dynamically) -->
    <div id="wizard-container">
        <div class="progress">
            <div class="progress-fill" id="progressFill"></div>
        </div>

        <!-- Dynamic Steps will be injected here -->
        <div id="dynamic-steps"></div>

        <!-- VERIFY SCREEN -->
        <div id="verify">
            <h2>Verify Information</h2>
            <div id="verify-list"></div>
            <div class="navigation">
                <button class="secondary" onclick="window.hideVerify()">Back to Edit</button>
                <button onclick="window.generateFinal()">Confirm & Generate</button>
            </div>
        </div>

        <!-- PREVIEW SCREEN -->
        <div id="preview">
            <h2 id="final-title">Final Report</h2>
            <div id="preview-list"></div>

            <div class="actions">
                <button id="exportBtn" onclick="window.downloadHtml()">Download HTML</button>
                <button id="copyBtn" onclick="window.copyToClipboard()">Copy to Clipboard</button>
                <button class="server-btn" id="serverBtn" onclick="window.saveToServer()">Save to Server</button>
                <button class="secondary" onclick="window.print()">Print / PDF</button>
            </div>
            <div id="copyFeedback">✓ Copied to clipboard!</div>
            
            <div id="serverFeedback">
                Report Saved! <br> 
                <a href="#" id="serverLink" target="_blank">Click here to view file</a>
            </div>
            
            <br>
            <button class="secondary" style="margin-top:20px" onclick="location.reload()">Start New Report</button>
        </div>
    </div>

</div>

<script>
    // --- REPORT CONFIGURATIONS ---
    const reportConfig = {
        SALT: {
            title: "SALT Report",
            fields: [
                { id: "size", label: "Size", help: "Number of personnel, vehicles, or elements.", placeholder: "E.g., 3 adult males, 2 SUVs..." },
                { id: "activity", label: "Activity", help: "What are they doing? Direction of travel?", placeholder: "E.g., Moving North rapidly..." },
                { id: "location", label: "Location", help: "Grid coordinates or landmark.", placeholder: "E.g., Grid 1234 5678 or Main St intersection..." },
                { id: "time", label: "Time", help: "Date and Time of observation.", placeholder: "Current time..." }
            ]
        },
        SALUTE: {
            title: "SALUTE Report",
            fields: [
                { id: "size", label: "Size", help: "Number of personnel or vehicles.", placeholder: "How many?" },
                { id: "activity", label: "Activity", help: "Actions, direction, movement.", placeholder: "What are they doing?" },
                { id: "location", label: "Location", help: "Grid, lat/long, or description.", placeholder: "Where are they?" },
                { id: "unit", label: "Unit / Uniform", help: "Patches, markings, uniform type.", placeholder: "Who are they?" },
                { id: "time", label: "Time", help: "DTG of observation.", placeholder: "When did you see this?" },
                { id: "equipment", label: "Equipment", help: "Weapons, sensors, vehicles.", placeholder: "What gear do they have?" }
            ]
        },
        SITREP: {
            title: "SITREP",
            fields: [
                { id: "time", label: "Time / Period", help: "Date Time Group (DTG) or period covered.", placeholder: "As of..." },
                { id: "enemy", label: "Enemy Situation", help: "Significant enemy activity during period.", placeholder: "Enemy activity observed..." },
                { id: "friendly", label: "Friendly Situation", help: "Location and status of friendly forces.", placeholder: "Unit location and status..." },
                { id: "logistics", label: "Logistics", help: "Supply status (Fuel, Ammo, Water, Med).", placeholder: "Green/Amber/Red..." },
                { id: "command", label: "Command & Signal", help: "Changes in freqs, location of command.", placeholder: "No changes..." }
            ]
        },
        INTREP: {
            title: "INTREP",
            fields: [
                { id: "time", label: "Time of Event", help: "When did the event occur?", placeholder: "DTG..." },
                { id: "location", label: "Location", help: "Where did the event occur?", placeholder: "Grid or Description..." },
                { id: "event", label: "Event Description", help: "Who, What, How?", placeholder: "Describe the event in detail..." },
                { id: "source", label: "Source", help: "How was this learned? (Observed, HUMINT, etc)", placeholder: "Visual observation..." },
                { id: "assessment", label: "Assessment", help: "What does this mean? Interpretation.", placeholder: "Significance..." }
            ]
        },
        TACTREP: {
            title: "TACTREP",
            fields: [
                { id: "time", label: "Time", help: "Date Time Group.", placeholder: "DTG..." },
                { id: "area", label: "Area", help: "Area of Interest or Operations.", placeholder: "Sector A..." },
                { id: "subject", label: "Subject", help: "The tactical event being reported.", placeholder: "Contact with patrol..." },
                { id: "action", label: "Action Taken", help: "Friendly actions taken.", placeholder: "Returned fire, broke contact..." }
            ]
        },
        TACELINT: {
            title: "TACELINT",
            fields: [
                { id: "freq", label: "Frequency", help: "Freq, Channel, or Band.", placeholder: "145.000 MHz..." },
                { id: "callsign", label: "Call Sign", help: "Observed call sign or identifier.", placeholder: "E.g., 'Red Leader'..." },
                { id: "modulation", label: "Modulation / Type", help: "AM, FM, USB, Digital type.", placeholder: "FM..." },
                { id: "location", label: "Location", help: "DF cut or Grid.", placeholder: "Est grid..." },
                { id: "time", label: "Time", help: "Time of intercept.", placeholder: "DTG..." },
                { id: "remarks", label: "Remarks", help: "Content of message or notes.", placeholder: "Traffic regarding..." }
            ]
        }
    };

    // --- STATE ---
    let currentReportKey = '';
    let currentFields = [];
    let currentStep = 1;

    // --- INITIALIZATION ---
    window.startReport = function(key) {
        currentReportKey = key;
        const config = reportConfig[key];
        currentFields = config.fields;
        
        // Update Header
        document.getElementById('app-title').innerText = config.title;
        document.getElementById('app-subtitle').innerText = "Complete the steps below";
        document.getElementById('final-title').innerText = config.title;

        // Hide Selection, Show Wizard
        document.getElementById('selection-screen').style.display = 'none';
        document.getElementById('wizard-container').style.display = 'block';

        // Build Interface
        buildSteps();
        buildVerify();
        buildPreview();

        // Auto-fill Time if present
        const timeField = document.getElementById('time');
        if(timeField) timeField.value = new Date().toLocaleString();

        // Show Step 1
        window.showStep(1);
    }

    // --- DOM BUILDERS ---
    function buildSteps() {
        const container = document.getElementById('dynamic-steps');
        container.innerHTML = '';

        currentFields.forEach((field, index) => {
            const stepNum = index + 1;
            const total = currentFields.length;
            
            const div = document.createElement('div');
            div.id = `step${stepNum}`;
            div.className = 'step';
            
            // Buttons logic
            let buttonsHtml = '';
            if (stepNum === 1) {
                buttonsHtml = `<button class="secondary" onclick="location.reload()">Back</button>
                               <button onclick="window.nextStep(${stepNum + 1})">Next</button>`;
            } else if (stepNum === total) {
                buttonsHtml = `<button class="secondary" onclick="window.prevStep(${stepNum - 1})">Back</button>
                               <button onclick="window.showVerify()">Review Report</button>`;
            } else {
                buttonsHtml = `<button class="secondary" onclick="window.prevStep(${stepNum - 1})">Back</button>
                               <button onclick="window.nextStep(${stepNum + 1})">Next</button>`;
            }

            div.innerHTML = `
                <label>${field.label}</label>
                <div class="helper-text">${field.help}</div>
                <textarea id="${field.id}" placeholder="${field.placeholder}"></textarea>
                <div class="navigation">${buttonsHtml}</div>
            `;
            container.appendChild(div);
        });
    }

    function buildVerify() {
        const container = document.getElementById('verify-list');
        container.innerHTML = '';
        currentFields.forEach(field => {
            container.innerHTML += `
                <div class="verify-item">
                    <strong>${field.label}</strong>
                    <textarea id="v-${field.id}"></textarea>
                </div>
            `;
        });
    }

    function buildPreview() {
        const container = document.getElementById('preview-list');
        container.innerHTML = '';
        currentFields.forEach(field => {
            container.innerHTML += `
                <div class="preview-item">
                    <strong>${field.label}</strong>
                    <p id="p-${field.id}"></p>
                </div>
            `;
        });
    }

    // --- NAVIGATION ---
    window.showStep = function(step) {
        document.querySelectorAll('.step').forEach(el => el.classList.remove('active'));
        const stepEl = document.getElementById(`step${step}`);
        if(stepEl) {
            stepEl.classList.add('active');
            updateProgress(step);
        }
    }

    window.nextStep = function(target) { window.showStep(target); }
    window.prevStep = function(target) { window.showStep(target); }

    function updateProgress(step) {
        const percent = ((step - 1) / currentFields.length) * 100;
        document.getElementById('progressFill').style.width = `${percent}%`;
    }

    // --- VERIFY & FINALIZE ---
    window.showVerify = function() {
        document.querySelectorAll('.step').forEach(el => el.classList.remove('active'));
        document.getElementById('verify').style.display = 'block';
        document.getElementById('progressFill').style.width = '100%';

        // Transfer values
        currentFields.forEach(field => {
            const mainVal = document.getElementById(field.id).value;
            document.getElementById(`v-${field.id}`).value = mainVal;
        });
        window.scrollTo(0,0);
    }

    window.hideVerify = function() {
        document.getElementById('verify').style.display = 'none';
        window.showStep(currentFields.length);
    }

    window.generateFinal = function() {
        // Sync back edits
        currentFields.forEach(field => {
            const val = document.getElementById(`v-${field.id}`).value;
            document.getElementById(field.id).value = val;
            const displayVal = val.trim() === '' ? '—' : val;
            document.getElementById(`p-${field.id}`).innerText = displayVal;
        });

        document.getElementById('verify').style.display = 'none';
        document.getElementById('preview').style.display = 'block';
        window.scrollTo(0,0);
    }

    // --- HELPER: GENERATE HTML STRING ---
    function getReportHtmlString() {
        const escapeHtml = (text) => text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
        
        let itemsHtml = '';
        currentFields.forEach(field => {
            let val = document.getElementById(field.id).value.trim();
            if(!val) val = "—";
            itemsHtml += `
                <div class="item">
                    <div class="label">${field.label}</div>
                    <div class="value">${escapeHtml(val)}</div>
                </div>`;
        });

        const title = reportConfig[currentReportKey].title;
        return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>${title}</title>
    <style>
        body { font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 40px; color: #333; line-height: 1.6; }
        header { border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
        h1 { margin: 0; font-size: 24px; text-transform: uppercase; letter-spacing: 1px; }
        .meta { color: #666; font-size: 14px; margin-top: 5px; }
        .item { margin-bottom: 25px; page-break-inside: avoid; }
        .label { font-size: 12px; font-weight: bold; text-transform: uppercase; color: #777; margin-bottom: 5px; letter-spacing: 0.5px; }
        .value { background: #f8f9fa; padding: 15px; border-left: 4px solid #007aff; border-radius: 4px; white-space: pre-wrap; font-size: 16px; }
    </style>
</head>
<body>
    <header>
        <h1>${title}</h1>
        <div class="meta">Generated: ${new Date().toLocaleString()}</div>
    </header>
    <div class="report-content">${itemsHtml}</div>
</body>
</html>`;
    }

    // --- COPY TO CLIPBOARD ---
    window.copyToClipboard = async function() {
        const data = currentFields.map(field => {
            let val = document.getElementById(field.id).value.trim();
            if(!val) val = "N/A";
            return `${field.label}: ${val}`;
        }).join('\n\n');

        const title = reportConfig[currentReportKey].title.toUpperCase();
        const reportText = `*** ${title} ***\n\n${data}\n\nGenerated: ${new Date().toLocaleString()}`;

        try {
            await navigator.clipboard.writeText(reportText);
            const feedback = document.getElementById('copyFeedback');
            feedback.style.display = 'block';
            setTimeout(() => { feedback.style.display = 'none'; }, 3000);
        } catch (err) {
            alert("Copy failed. Please copy manually.");
        }
    }

    // --- DOWNLOAD HTML (Client Side) ---
    window.downloadHtml = function() {
        const fileContent = getReportHtmlString();
        const title = reportConfig[currentReportKey].title;
        const blob = new Blob([fileContent], {type: 'text/html'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${title.replace(/\s/g, '_')}_${new Date().toISOString().slice(0,10)}.html`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // --- SAVE TO SERVER ---
    window.saveToServer = async function() {
        const btn = document.getElementById('serverBtn');
        const feedback = document.getElementById('serverFeedback');
        const link = document.getElementById('serverLink');
        
        btn.disabled = true;
        btn.innerText = "Saving...";

        const htmlContent = getReportHtmlString();

        try {
            const response = await fetch('', { 
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    html: htmlContent,
                    type: currentReportKey
                })
            });
            
            const contentType = response.headers.get("content-type");
            if (!contentType || !contentType.includes("application/json")) {
                throw new Error("Session expired. Please reload and login.");
            }

            if (!response.ok) throw new Error("Server error");
            const result = await response.json();

            if (result.success) {
                feedback.style.display = 'block';
                link.href = result.url;
                btn.innerText = "Saved";
            } else {
                alert("Error: " + result.error);
                btn.disabled = false;
                btn.innerText = "Save to Server";
            }
        } catch (error) {
            console.error(error);
            alert("Save Failed: " + error.message);
            btn.disabled = false;
            btn.innerText = "Save to Server";
        }
    }
</script>

</body>
</html>
