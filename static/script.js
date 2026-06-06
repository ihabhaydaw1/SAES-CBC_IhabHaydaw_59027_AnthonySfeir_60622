document.addEventListener('DOMContentLoaded', () => {
    // --- Tabs Logic ---
    const tabBtns = document.querySelectorAll('.tab-btn');
    const panels = document.querySelectorAll('.panel');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            // Remove active from all
            tabBtns.forEach(b => b.classList.remove('active'));
            panels.forEach(p => p.classList.remove('active'));

            // Add active to clicked
            btn.classList.add('active');
            const targetId = btn.getAttribute('data-target');
            document.getElementById(targetId).classList.add('active');
        });
    });

    // --- File Drag & Drop Logic ---
    function setupDragDrop(dropAreaId, inputId, nameId) {
        const dropArea = document.getElementById(dropAreaId);
        const input = document.getElementById(inputId);
        const nameDisplay = document.getElementById(nameId);

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropArea.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        ['dragenter', 'dragover'].forEach(eventName => {
            dropArea.addEventListener(eventName, () => dropArea.classList.add('dragover'), false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropArea.addEventListener(eventName, () => dropArea.classList.remove('dragover'), false);
        });

        dropArea.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            input.files = files;
            updateFileName();
        });

        input.addEventListener('change', updateFileName);

        function updateFileName() {
            if (input.files.length > 0) {
                nameDisplay.textContent = input.files[0].name;
            } else {
                nameDisplay.textContent = '';
            }
        }
    }

    setupDragDrop('ed-drop-area', 'ed-file', 'ed-file-name');
    setupDragDrop('bf-drop-area', 'bf-file', 'bf-file-name');

    // --- Forms Submission ---

    // Encrypt / Decrypt Form
    const edForm = document.getElementById('ed-form');
    const edResult = document.getElementById('ed-result');
    const edActionInput = document.getElementById('ed-action');

    // Make functions globally available for inline onclick
    window.setEDAction = function(action) {
        edActionInput.value = action;
    };

    edForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        edResult.classList.add('hidden');
        edResult.className = 'result-box'; // reset
        
        const formData = new FormData(edForm);
        
        try {
            const res = await fetch('/api/process_file', {
                method: 'POST',
                body: formData
            });

            if (res.ok) {
                // Trigger download
                const blob = await res.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                
                // Get filename from header if possible, else default
                let filename = formData.get('action') + "ed_file";
                const disposition = res.headers.get('Content-Disposition');
                if (disposition && disposition.indexOf('attachment') !== -1) {
                    const filenameRegex = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/;
                    const matches = filenameRegex.exec(disposition);
                    if (matches != null && matches[1]) { 
                        filename = matches[1].replace(/['"]/g, '');
                    }
                }
                
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);

                edResult.textContent = `Success! File downloaded as ${filename}`;
                edResult.classList.add('success');
            } else {
                const data = await res.json();
                edResult.textContent = `Error: ${data.error || 'Unknown error'}`;
                edResult.classList.add('error');
            }
        } catch (err) {
            edResult.textContent = `Error: ${err.message}`;
            edResult.classList.add('error');
        }
        edResult.classList.remove('hidden');
    });

    // Brute Force Form
    const bfForm = document.getElementById('bf-form');
    const bfResult = document.getElementById('bf-result');
    const bfLoading = document.getElementById('bf-loading');

    bfForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        bfResult.classList.add('hidden');
        bfResult.className = 'result-box';
        bfLoading.classList.remove('hidden');
        
        const formData = new FormData(bfForm);

        try {
            const res = await fetch('/api/brute_force', {
                method: 'POST',
                body: formData
            });

            const data = await res.json();
            bfLoading.classList.add('hidden');

            if (res.ok) {
                if (data.success) {
                    bfResult.textContent = `Attack Successful! Found Key: ${data.found_key}`;
                    bfResult.classList.add('success');
                } else {
                    bfResult.textContent = `Attack Failed: ${data.message}`;
                    bfResult.classList.add('error');
                }
            } else {
                bfResult.textContent = `Error: ${data.error || 'Unknown error'}`;
                bfResult.classList.add('error');
            }
        } catch (err) {
            bfLoading.classList.add('hidden');
            bfResult.textContent = `Error: ${err.message}`;
            bfResult.classList.add('error');
        }
        bfResult.classList.remove('hidden');
    });
});
