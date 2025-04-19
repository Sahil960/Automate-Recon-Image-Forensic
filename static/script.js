// static/script.js
document.addEventListener('DOMContentLoaded', () => {
    // --- Get Recon Elements ---
    const runSelectedScansBtn = document.getElementById('run-selected-scans-btn');
    const targetInput = document.getElementById('target');
    const loadingDiv = document.getElementById('loading');
    const errorMessageDiv = document.getElementById('error-message');
    const resultsArea = document.getElementById('results-area');
    const passiveResultsSection = document.getElementById('passive-results-section');
    const activeResultsSection = document.getElementById('active-results-section');
    const targetDisplays = document.querySelectorAll('.target-display');
    // Passive Recon Result Elements
    const whoisBlock = document.getElementById('whois-block');
    const whoisResultsPre = document.getElementById('whois-results');
    const dnsBlock = document.getElementById('dns-block');
    const dnsResultsPre = document.getElementById('dns-results');
    const ctLogsBlock = document.getElementById('ct_logs-block');
    const crtshResultsPre = document.getElementById('crtsh-results');
    const techPassiveBlock = document.getElementById('tech_passive-block');
    const passiveTechResultsDiv = document.getElementById('passive-tech-results-content');
    const githubBlock = document.getElementById('github-block');
    const githubResultsDiv = document.getElementById('github-results-content');
    const waybackBlock = document.getElementById('wayback-block');
    const waybackResultsDiv = document.getElementById('wayback-results-content');
    const serpapiBlock = document.getElementById('serpapi-block');
    const serpapiResultsDiv = document.getElementById('serpapi-results-content');
    const manualPassiveBlock = document.getElementById('manual-passive-block');
    const manualDorksResultsPre = document.getElementById('manual-dorks-results');
    const shodanCensysDiv = document.getElementById('shodan-censys-results');
    const manualChecksUl = document.getElementById('manual-checks-results');
    // Active Recon Result Elements
    const nmapBlock = document.getElementById('nmap-block');
    const portscanResultsPre = document.getElementById('portscan-results');
    const crawlBlock = document.getElementById('crawl-block');
    const crawlResultsPre = document.getElementById('crawl-results');
    const techActiveBlock = document.getElementById('tech_active-block');
    const activeTechResultsDiv = document.getElementById('active-tech-results-content');
    const axfrBlock = document.getElementById('axfr-block');
    const zonetransferResultsPre = document.getElementById('zonetransfer-results');
    const fuzzBlock = document.getElementById('fuzz-block');
    const fuzzingResultsPre = document.getElementById('fuzzing-results');
    const vulnHintBlock = document.getElementById('vuln-hint-block');
    const activeVulnSuggestionP = document.getElementById('active-vuln-suggestion');

    // --- Get Forensic Elements ---
    const imageUploadInput = document.getElementById('image-upload');
    const analyzeImageBtn = document.getElementById('analyze-image-btn');
    const forensicLoadingDiv = document.getElementById('forensic-loading');
    const forensicErrorMessageDiv = document.getElementById('forensic-error-message');
    const imageMetadataResultsDiv = document.getElementById('image-metadata-results');
    const imageFilenameDisplay = document.getElementById('image-filename-display');
    const metadataContentDiv = document.getElementById('metadata-content');
    const gpsContentDiv = document.getElementById('gps-content');
    // const mapDisplayDiv = document.getElementById('map-display'); // Uncomment if using Leaflet


    // --- Event Listeners ---
    if (runSelectedScansBtn) runSelectedScansBtn.addEventListener('click', runReconScan); // Attach to recon button
    if (analyzeImageBtn) analyzeImageBtn.addEventListener('click', analyzeImage); // Attach to forensic button


    // --- General UI Helpers ---
    function showLoading(element, isLoading) { element.style.display = isLoading ? 'block' : 'none'; }
    function showError(element, message) { element.textContent = message; element.style.display = 'block'; }
    function hideError(element) { element.style.display = 'none'; element.textContent = ''; }
    function updateTargetDisplays(target) { targetDisplays.forEach(span => { span.textContent = target ? escapeHtml(target) : ''; }); }
    function escapeHtml(unsafe) { if (unsafe === null || unsafe === undefined) return ''; return unsafe.toString().replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); }
    function formatJsonOrError(data) {
        if (typeof data === 'string') { return escapeHtml(data); }
        if (data && data.error) { return `<span class="error">Error: ${escapeHtml(JSON.stringify(data.error, null, 2))}</span>`; } // Wrap error in span
        if (data && data.info) { return `Info: ${escapeHtml(JSON.stringify(data.info, null, 2))}`; }
        try {
            // Attempt to format nicely, handle potential large objects
            const jsonString = JSON.stringify(data, null, 2);
            // Basic check for excessive length before escaping
            if (jsonString.length > 20000) { // Limit length to prevent browser freeze
                 return escapeHtml(jsonString.substring(0, 20000)) + "\n... (output truncated due to length)";
            }
            return escapeHtml(jsonString);
        } catch (e) {
            console.error("Format error:", data, e);
            // Fallback for very large/complex objects that might fail stringify or escaping
            return "<span class='error'>Error formatting data (object might be too large or complex). Check console.</span>";
        }
    }

    // --- Recon Scan Functions ---
    function runReconScan() {
        const target = targetInput.value.trim();
        if (!target) { showError(errorMessageDiv, "Please enter a target domain or IP address."); return; }

        const checkedTasks = document.querySelectorAll('input[name="tasks"]:checked');
        const selectedTaskIds = Array.from(checkedTasks).map(cb => cb.value);

        if (selectedTaskIds.length === 0) {
            showError(errorMessageDiv, "Please select at least one recon scan task.");
            return;
        }

        clearReconResults(); // Clear only recon results
        hideError(errorMessageDiv); // Hide recon error message specifically
        showLoading(loadingDiv, true);
        runSelectedScansBtn.disabled = true;
        updateTargetDisplays(target);

        console.log("Running Recon scans for:", target, "Tasks:", selectedTaskIds);

        fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: target, tasks: selectedTaskIds })
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => {
                    throw new Error(err.error || `HTTP ${response.status}: ${response.statusText}`);
                }).catch(() => {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                });
            }
            return response.json();
        })
        .then(data => {
            showLoading(loadingDiv, false);
            runSelectedScansBtn.disabled = false;
            if (data.error) { // Check for top-level error from Flask (e.g., validation)
                showError(errorMessageDiv, data.error);
            } else {
                displayReconResults(data); // Display results even if some tasks had errors internally
            }
        })
        .catch(error => {
            showLoading(loadingDiv, false);
            runSelectedScansBtn.disabled = false;
            showError(errorMessageDiv, `Recon fetch/processing error: ${error.message}`);
            console.error('Recon Fetch error:', error);
        });
    }

    function clearReconResults() {
        // Don't hide the error message here, do it in runReconScan start
        passiveResultsSection.style.display = 'none';
        activeResultsSection.style.display = 'none';

        // Hide individual recon result blocks
        const reconResultBlocks = resultsArea.querySelectorAll('#passive-results-section .result-block, #active-results-section .result-block');
        reconResultBlocks.forEach(block => { block.style.display = 'none'; });

        // Clear content of recon elements
        whoisResultsPre.textContent = '';
        dnsResultsPre.textContent = '';
        crtshResultsPre.textContent = '';
        passiveTechResultsDiv.innerHTML = '';
        githubResultsDiv.innerHTML = '';
        waybackResultsDiv.innerHTML = '';
        serpapiResultsDiv.innerHTML = '';
        manualDorksResultsPre.textContent = '';
        shodanCensysDiv.innerHTML = '';
        manualChecksUl.innerHTML = '';
        portscanResultsPre.textContent = '';
        crawlResultsPre.textContent = '';
        activeTechResultsDiv.innerHTML = '';
        zonetransferResultsPre.textContent = '';
        fuzzingResultsPre.textContent = '';
        activeVulnSuggestionP.textContent = '';

        updateTargetDisplays(''); // Clear target display specific to recon sections
    }

    function displayReconResults(data) {
        const results = data.results || {};
        let passiveDisplayed = false;
        let activeDisplayed = false;

        // --- Populate Recon Results ---
        for (const taskId in results) {
            const resultData = results[taskId];
            // Don't skip if null/undefined, allow formatJsonOrError to handle it or show N/A
            // if (!resultData) continue;

            switch (taskId) {
                // --- Passive ---
                case 'whois':
                    whoisResultsPre.innerHTML = formatJsonOrError(resultData); // Use innerHTML for potential error spans
                    whoisBlock.style.display = 'block'; passiveDisplayed = true; break;
                case 'dns':
                    dnsResultsPre.innerHTML = formatJsonOrError(resultData);
                    dnsBlock.style.display = 'block'; passiveDisplayed = true; break;
                case 'ct_logs':
                    // Handle crt.sh data structure (list or error dict)
                    if (resultData && resultData.error) {
                        crtshResultsPre.innerHTML = `<span class="error">Error: ${escapeHtml(resultData.error)}</span>`;
                    } else if (resultData && Array.isArray(resultData.data)) {
                        crtshResultsPre.textContent = resultData.data.length > 0 ? resultData.data.map(escapeHtml).join('\n') : 'No subdomains found via crt.sh';
                    } else {
                         crtshResultsPre.textContent = 'N/A or unexpected format'; // Fallback
                    }
                    ctLogsBlock.style.display = 'block'; passiveDisplayed = true; break;
                case 'tech_passive':
                    displayTechResults(resultData, passiveTechResultsDiv);
                    techPassiveBlock.style.display = 'block'; passiveDisplayed = true; break;
                case 'github':
                    displayGitHubResults(resultData, githubResultsDiv);
                    githubBlock.style.display = 'block'; passiveDisplayed = true; break;
                case 'wayback':
                    displayWaybackResults(resultData, waybackResultsDiv);
                    waybackBlock.style.display = 'block'; passiveDisplayed = true; break;
                case 'serpapi':
                    displaySerpApiResults(resultData, serpapiResultsDiv);
                    serpapiBlock.style.display = 'block'; passiveDisplayed = true; break;
                // --- Active ---
                case 'nmap':
                    portscanResultsPre.innerHTML = formatJsonOrError(resultData);
                    nmapBlock.style.display = 'block'; activeDisplayed = true; break;
                case 'crawl':
                    crawlResultsPre.innerHTML = formatJsonOrError(resultData);
                    crawlBlock.style.display = 'block'; activeDisplayed = true; break;
                case 'tech_active':
                    displayTechResults(resultData, activeTechResultsDiv);
                    techActiveBlock.style.display = 'block'; activeDisplayed = true; break;
                case 'axfr':
                    zonetransferResultsPre.innerHTML = formatJsonOrError(resultData);
                    axfrBlock.style.display = 'block'; activeDisplayed = true; break;
                case 'fuzz':
                    fuzzingResultsPre.innerHTML = formatJsonOrError(resultData);
                    fuzzBlock.style.display = 'block'; activeDisplayed = true; break;
                // --- Manual Info (Added by backend) ---
                case 'manual_google_dorks':
                    if (resultData && resultData.info && resultData.examples) {
                        manualDorksResultsPre.textContent = `${escapeHtml(resultData.info)}\n\n${resultData.examples.map(escapeHtml).join('\n')}`;
                        manualPassiveBlock.style.display = 'block'; passiveDisplayed = true; // Show parent block if any manual info exists
                    } break;
                case 'shodan_censys':
                    if (resultData && resultData.info && resultData.links) {
                        shodanCensysDiv.innerHTML = `<p>${escapeHtml(resultData.info)}</p><ul>${resultData.links.map(l => `<li><a href="${escapeHtml(l)}" target="_blank">${escapeHtml(l)}</a></li>`).join('')}</ul>`;
                        manualPassiveBlock.style.display = 'block'; passiveDisplayed = true;
                    } break;
                case 'manual_checks':
                    if (resultData && Array.isArray(resultData)) {
                        manualChecksUl.innerHTML = resultData.map(item => `<li>${escapeHtml(item)}</li>`).join('');
                        manualPassiveBlock.style.display = 'block'; passiveDisplayed = true;
                    } break;
                case 'manual_vuln_check_suggestion':
                    if (resultData) {
                        activeVulnSuggestionP.textContent = escapeHtml(resultData);
                        vulnHintBlock.style.display = 'block'; activeDisplayed = true;
                    } break;
                default: console.warn("Received results for unknown recon task ID:", taskId); break;
            }
        }

        // --- Show Sections ---
        if (passiveDisplayed) passiveResultsSection.style.display = 'block';
        if (activeDisplayed) activeResultsSection.style.display = 'block';

        // Check if *any* task ran but nothing was displayed (e.g., all results were errors handled internally by display funcs)
        const ranTasks = Object.keys(results);
        if (ranTasks.length > 0 && !passiveDisplayed && !activeDisplayed) {
             // Check if there's already a top-level error message shown
             if (errorMessageDiv.style.display !== 'block') {
                  showError(errorMessageDiv, "Scan completed, but no displayable results generated (tasks might have failed or returned no data). Check console for details.");
             }
        } else if (ranTasks.length === 0 && !data.error) { // No tasks ran, no top-level error
             console.log("No recon results returned from backend.");
             // Optionally show info message? Maybe not necessary if no tasks were selected.
        }
    }

    // --- Recon Specific Display Helpers (minor tweaks for robustness) ---
    function displayTechResults(d, el) { el.innerHTML = ''; if(!d) {el.innerHTML='<p>N/A</p>'; return;} if(d.error){el.innerHTML=`<p class="error">Error: ${escapeHtml(d.error)}</p>`; return;} let c=''; if(d.technologies && Array.isArray(d.technologies) && d.technologies.length > 0){ c+='<ul>'; d.technologies.forEach(t=>{ if(t && t.name) c+=`<li><strong>${escapeHtml(t.name)}</strong>${t.version?` (v${escapeHtml(t.version)})`:''}</li>`;}); c+='</ul>'; } else if(d.info){ c=`<p>${escapeHtml(d.info)}</p>`; } else { c=`<p>No specific technologies detected.</p>`;} el.innerHTML=c; }
    function displayGitHubResults(d, el) { el.innerHTML = ''; if(!d) {el.innerHTML='<p>N/A</p>'; return;} if(d.error){el.innerHTML=`<p class="error">Error: ${escapeHtml(d.error)}</p>`; return;} let c=''; if(d.info){c+=`<p>${escapeHtml(d.info)}</p>`;} const repos = d.repositories || []; const snippets = d.code_snippets || []; if(repos.length > 0){ c+='<h6>Repositories:</h6><ul>'; repos.forEach(r=>{ if(r && r.url && r.name) c+=`<li><a href="${escapeHtml(r.url)}" target="_blank"><strong>${escapeHtml(r.name)}</strong></a> (Stars: ${escapeHtml(r.stars||'N/A')})<br><small>${escapeHtml(r.description)||'N/A'}. Updated: ${escapeHtml(r.last_updated||'?')}</small></li>`;}); c+='</ul>';} else { c+='<p>No relevant repositories found.</p>';} if(snippets.length > 0){ c+='<h6 style="margin-top: 15px;">Potential Code Snippets:</h6><ul>'; snippets.forEach(s=>{ if(!s) return; if(s.error){ c+=`<li><span class="error">Error: ${escapeHtml(s.error)}</span></li>`; } else if (s.url && s.filename && s.repo && s.query_matched) { c+=`<li><a href="${escapeHtml(s.url)}" target="_blank"><strong>${escapeHtml(s.filename)}</strong></a> in <i>${escapeHtml(s.repo)}</i><br><small>Query: "${escapeHtml(s.query_matched)}"</small></li>`;} else {c+=`<li><span class="error">Incomplete snippet data received.</span></li>`}}); c+='</ul>';} else if (repos.length === 0){ c+='<p>No relevant code snippets found.</p>';} el.innerHTML=c||'<p>N/A</p>'; }
    function displayWaybackResults(d, el) { el.innerHTML = ''; if(!d) {el.innerHTML='<p>N/A</p>'; return;} if(d.error){el.innerHTML=`<p class="error">Error: ${escapeHtml(d.error)}</p>`; return;} let c=''; let contentFound = false; if(d.info){c+=`<p>${escapeHtml(d.info)}</p>`; contentFound = true;} if(d.oldest_snapshot_url){c+=`<p><strong>Oldest:</strong> <a href="${escapeHtml(d.oldest_snapshot_url)}" target="_blank">${escapeHtml(d.oldest_snapshot_time||'?')}</a></p>`; contentFound = true;} if(d.newest_snapshot_url){c+=`<p><strong>Newest:</strong> <a href="${escapeHtml(d.newest_snapshot_url)}" target="_blank">${escapeHtml(d.newest_snapshot_time||'?')}</a></p>`; contentFound = true;} const snaps = d.snapshots || []; if(snaps.length > 0){ c+='<h6 style="margin-top: 15px;">Recent/Known Snapshots:</h6><ul>'; snaps.forEach(s=>{ if(s && s.archive_url) c+=`<li><a href="${escapeHtml(s.archive_url)}" target="_blank">${escapeHtml(s.timestamp||'?')}</a> (Status: ${escapeHtml(s.status||'?')})<br><small>URL: ${escapeHtml(s.url||'?')}</small></li>`;}); c+='</ul>'; contentFound = true;} if (!contentFound) { c= '<p>No snapshot data found.</p>'} el.innerHTML=c||'<p>N/A</p>'; }
    function displaySerpApiResults(d, el) { el.innerHTML = ''; if(!d) {el.innerHTML='<p>N/A</p>'; return;} if(d.error){el.innerHTML=`<p class="error">Error: ${escapeHtml(d.error)}</p>`; return;} let contentFound = false; let h = ''; if (d.info) { h+=`<p>${escapeHtml(d.info)}</p>`; contentFound = true;} if(d.dorks && Object.keys(d.dorks).length > 0){ h+=`<dl>`; for(const k in d.dorks){ h+=`<dt><strong>${escapeHtml(k)}</strong></dt>`; const res=d.dorks[k]; if(res && Array.isArray(res) && res.length > 0){ res.forEach(i=>{ if(!i) return; h+=`<dd>`; if(i.error){h+=`<span class="error">Error: ${escapeHtml(i.error)}</span>`;} else if(i.info){h+=`<span>${escapeHtml(i.info)}</span>`;} else if(i.link && i.title && i.snippet) {h+=`<a href="${escapeHtml(i.link)}" target="_blank">${escapeHtml(i.title)}</a><br><small>${escapeHtml(i.snippet)}</small>`;} else {h+=`<span>Incomplete result data.</span>`} h+=`</dd>`;}); contentFound = true;} else {h+=`<dd>No results for this dork.</dd>`;}} h+=`</dl>`; } if (!contentFound) { h = `<p>No dork results or info provided.</p>`;} el.innerHTML = h;}


    // --- Forensic Analysis Functions ---
    function analyzeImage() {
        if (!imageUploadInput || !imageUploadInput.files || imageUploadInput.files.length === 0) {
            showError(forensicErrorMessageDiv, "Please select an image file first.");
            return;
        }
        const file = imageUploadInput.files[0];

        // Client-side size check (optional but good UX)
        const maxSizeMB = 15; // Slightly less than server limit
        if (file.size > maxSizeMB * 1024 * 1024) {
             showError(forensicErrorMessageDiv, `File is too large (${(file.size / 1024 / 1024).toFixed(1)} MB). Maximum size is ${maxSizeMB} MB.`);
             imageUploadInput.value = ''; // Clear the input
             return;
        }


        clearForensicResults(); // Clear previous forensic results
        hideError(forensicErrorMessageDiv); // Hide forensic error specifically
        showLoading(forensicLoadingDiv, true);
        analyzeImageBtn.disabled = true;

        const formData = new FormData();
        formData.append('image_file', file);

        console.log("Analyzing image:", file.name);

        fetch('/analyze_image', {
            method: 'POST',
            body: formData // Browser sets Content-Type automatically for FormData
        })
        .then(response => {
             if (!response.ok) {
                 // Try to parse JSON error first
                 return response.json().then(err => {
                     // Use err.error if available, otherwise construct from status
                     throw new Error(err.error || `Analysis failed with status ${response.status} (${response.statusText})`);
                 }).catch(() => { // Fallback if error response is not JSON
                     throw new Error(`Analysis failed with status ${response.status} (${response.statusText})`);
                 });
             }
             return response.json();
         })
        .then(data => {
            showLoading(forensicLoadingDiv, false);
            analyzeImageBtn.disabled = false;
            if (data.error) { // Check for top-level error from backend (e.g., Pillow not installed)
                showError(forensicErrorMessageDiv, data.error);
            } else {
                displayImageMetadata(data);
            }
        })
        .catch(error => {
            showLoading(forensicLoadingDiv, false);
            analyzeImageBtn.disabled = false;
            showError(forensicErrorMessageDiv, `Analysis error: ${error.message}`);
            console.error('Image Analysis error:', error);
        });
    }

    function clearForensicResults() {
        // Don't hide the error message here
        imageMetadataResultsDiv.style.display = 'none';
        metadataContentDiv.innerHTML = '';
        gpsContentDiv.innerHTML = '';
        imageFilenameDisplay.textContent = '';
        // if (mapDisplayDiv) mapDisplayDiv.innerHTML = ''; // Clear map if using one
    }

    function displayImageMetadata(data) {
        hideError(forensicErrorMessageDiv); // Hide any previous error
        imageMetadataResultsDiv.style.display = 'block';
        imageFilenameDisplay.textContent = escapeHtml(data.filename || 'N/A');

        // --- Display GPS Data First (if found) ---
        let gpsHtml = '';
        if (data.gps_coordinates && typeof data.gps_coordinates.latitude === 'number' && typeof data.gps_coordinates.longitude === 'number') {
            const lat = data.gps_coordinates.latitude;
            const lon = data.gps_coordinates.longitude;
            const alt = data.gps_coordinates.altitude; // Might be undefined
            const altRef = data.gps_coordinates.altitude_ref; // Might be undefined

            // Format altitude string if available
            let altString = '';
            if (alt !== undefined && alt !== null && typeof alt === 'number') {
                 altString = `<br>Altitude: ${escapeHtml(alt.toFixed(2))} meters ${escapeHtml(altRef || '')}`;
            }

            gpsHtml = `<h6><span class="gps-icon"></span> GPS Coordinates Found:</h6>
                       <p>Latitude: ${escapeHtml(lat.toFixed(6))}<br>
                          Longitude: ${escapeHtml(lon.toFixed(6))}
                          ${altString}
                       </p>
                       <p class="map-links">
                            <a href="https://www.google.com/maps?q=${lat},${lon}" target="_blank" title="View on Google Maps">Google Maps</a> |
                            <a href="https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=16/${lat}/${lon}" target="_blank" title="View on OpenStreetMap">OpenStreetMap</a>
                       </p>`;

            // --- Optional: Leaflet Map Integration ---
            // if (typeof L !== 'undefined' && mapDisplayDiv) {
            //     mapDisplayDiv.innerHTML = ''; // Clear previous map
            //     try {
            //         const map = L.map(mapDisplayDiv).setView([lat, lon], 13); // Initial zoom level 13
            //         L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            //             attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
            //             maxZoom: 18, // Optional: Set max zoom
            //         }).addTo(map);
            //         L.marker([lat, lon]).addTo(map)
            //             .bindPopup(`Location from ${escapeHtml(data.filename || 'image')}<br>Lat: ${lat.toFixed(4)}, Lon: ${lon.toFixed(4)}`)
            //             .openPopup();
            //         mapDisplayDiv.style.display = 'block'; // Make sure map div is visible
            //     } catch(mapError) {
            //         console.error("Leaflet map initialization error:", mapError);
            //         mapDisplayDiv.innerHTML = '<p class="error">Could not initialize map.</p>';
            //         mapDisplayDiv.style.display = 'block';
            //     }
            // } else if (mapDisplayDiv) {
            //     mapDisplayDiv.style.display = 'none'; // Hide map div if Leaflet not loaded
            // }
            // --- End Optional Leaflet ---

        } else {
            gpsHtml = '<p>No GPS coordinates found or calculable in this image.</p>';
            // if (mapDisplayDiv) mapDisplayDiv.style.display = 'none'; // Hide map div if no coords
        }
        gpsContentDiv.innerHTML = gpsHtml;

        // --- Display Other Metadata ---
        let metadataHtml = '';
        if (data.metadata) {
            if (data.metadata.error) {
                 metadataHtml = `<p class="error">Error extracting metadata: ${escapeHtml(data.metadata.error)}</p>`;
            } else if (data.metadata.info) {
                 metadataHtml = `<p>${escapeHtml(data.metadata.info)}</p>`;
            } else if (Object.keys(data.metadata).length > 0) {
                metadataHtml = '<h6>Other Metadata:</h6><dl>'; // Use definition list
                // Sort keys alphabetically for consistent display
                const sortedKeys = Object.keys(data.metadata).sort();

                for (const key of sortedKeys) {
                    // Skip GPSInfo dictionary here, already handled
                    if (key === 'GPSInfo') continue;

                    // Filter potentially very large or problematic tags
                    const omitTags = ['MakerNote', 'UserComment', 'ThumbnailOffset', 'ThumbnailLength', 'Padding']; // Add more if needed
                    if (omitTags.includes(key)) {
                        metadataHtml += `<dt><strong>${escapeHtml(key)}</strong></dt><dd><i>(Data omitted for brevity/display)</i></dd>`;
                        continue;
                    }

                    let value = data.metadata[key];
                    // Check if value is an object (like DateTimeOriginal potentially) - display as string
                    if (typeof value === 'object' && value !== null) {
                        value = JSON.stringify(value); // Simple stringification for objects
                    }
                    let displayValue = escapeHtml(String(value)); // Ensure string and escape

                    metadataHtml += `<dt><strong>${escapeHtml(key)}</strong></dt><dd>${displayValue}</dd>`;
                }
                metadataHtml += '</dl>';
            } else {
                 // Metadata object was present but empty (after filtering GPSInfo etc)
                 metadataHtml = '<p>No other metadata found or extracted.</p>';
            }
        } else {
             // The 'metadata' key was missing from the response entirely
             metadataHtml = '<p class="error">Metadata section not found in server response.</p>';
        }
        metadataContentDiv.innerHTML = metadataHtml;

    } // End displayImageMetadata


}); // End DOMContentLoaded

// --- Global Helper Functions (like showTab) needed outside DOMContentLoaded ---
function showTab(tabId, clickedButton) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    // Deactivate all buttons
     document.querySelectorAll('.tab-button').forEach(button => {
        button.classList.remove('active');
    });

    // Show the selected tab
    const selectedTab = document.getElementById(tabId);
    if (selectedTab) {
        selectedTab.classList.add('active');
    }
    // Activate the clicked button
    if (clickedButton) {
         clickedButton.classList.add('active');
    }
}

// Ensure the tab initialization logic runs *after* the main DOMContentLoaded listener
// This prevents potential race conditions if showTab relies on elements selected inside the main listener.
// Alternatively, move the tab initialization *inside* the main DOMContentLoaded listener if showTab doesn't
// need to be global (which it doesn't seem to, based on the HTML). Let's move it inside.
// *** Moved tab initialization logic inside DOMContentLoaded in index.html ***