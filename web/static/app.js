$(document).ready(function() {
    const statisticsTableManager = new StatisticsTableManager();
    const packetTableManager = new PacketTableManager();
    const flowStatisticsManager = new FlowStatisticsTableManager();
    window.alertManager = new AlertManager();

    let captureStarted = false;
    let intervals = [];
    let captureCheckInterval = null;

    function fetchStatistics() {
        FetchService.getData('/statistics', stats => {
            statisticsTableManager.populateStatistics(stats);
        }, () => console.error('Error fetching statistics'));
    }

    function fetchPackets() {
        FetchService.fetchJSON('/packets', packets => packetTableManager.populatePackets(packets), console.error);
    }

    function fetchFlowStatistics() {
        FetchService.getData('/flow_statistics', flowStats => flowStatisticsManager.populateFlowStatistics(flowStats));
    }

    function fetchAlerts() {
        FetchService.getData('/detector_alerts', alerts => {
            window.alertManager.displayAlerts(alerts);
        });
    }
    function checkCaptureFile() {
        $.get('/check_capture', function (data) {
            if (data.capture_available) {
                $('#downloadContainer').show(); 
                clearInterval(captureCheckInterval); 
            }
        });
    }

    // Start polling for stats
    function startPolling() {
        intervals.push(setInterval(fetchStatistics, 2000));
        intervals.push(setInterval(fetchPackets, 2000));
        intervals.push(setInterval(fetchFlowStatistics, 2000));
        intervals.push(setInterval(fetchAlerts, 2000));
        captureCheckInterval = setInterval(checkCaptureFile, 5000);
    }

    // Stop polling
    function stopPolling() {
        intervals.forEach(interval => clearInterval(interval));
        clearInterval(captureCheckInterval); // Stop checking capture file
        intervals = [];
    }
    $('#startCaptureForm').submit(function(event) {
        event.preventDefault();
    
        if (!captureStarted) {
            captureStarted = true;
    
            const formData = $(this).serialize();
    
            $.post('/start_sniffer', formData)
                .done(function(response) {
                    alert(response.status);  // Show success message
                    startPolling();  // Start polling after sniffer is started
                })
                .fail(function(response) {
                    alert(response.responseJSON.error);  // Show error message
                    captureStarted = false;  // Reset captureStarted if failed
                });
        } else {
            alert('Sniffer is already running.');
        }
    });

    $('#stopSnifferForm').submit(function(event) {
        event.preventDefault();
    
        if (captureStarted) {
            $.post('/stop_sniffer')
                .done(function(response) {
                    alert(response.status);  // Show success message
    
                    // Ask the user if they want to reset the page or keep the current state
                    let resetDecision = confirm("Do you want to reset the page and clear all settings?");
    
                    if (resetDecision) {
                        // If the user chooses to reset, redirect to the index page
                        window.location.href = '/';
                    } else {
                        // If the user chooses not to reset, simply stop the polling and keep the page as is
                        stopPolling();  // Stop the current polling
                        captureStarted = false;  // Reset captureStarted flag
                        
                        // Show the refresh button for manual reset option
                        $('#refreshPageButton').show();
                    }
                })
                .fail(function(response) {
                    alert(response.responseJSON.error);  // Show error message
                });
        } else {
            alert('No sniffer is currently running.');
        }
    });
    
    // Refresh the page when the refresh button is clicked
    $('#refreshPageButton').click(function() {
        location.reload();  // Refresh the page, resetting everything
    });
    
    
    

});
