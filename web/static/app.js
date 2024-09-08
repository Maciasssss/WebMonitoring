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

    // Form submission via AJAX
    $('#startCaptureForm').submit(function(event) {
        event.preventDefault();

        if (!captureStarted) {
            captureStarted = true;

            const formData = $(this).serialize();

            $.post('/start_sniffer', formData)
                .done(function() {
                    alert('Packet sniffer started!');
                    startPolling();
                })
                .fail(function() {
                    alert('Failed to start the sniffer.');
                    captureStarted = false;
                });
        } else {
            alert('Sniffer is already running.');
        }
    });
});
