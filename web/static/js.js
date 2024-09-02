$(document).ready(function() {
    var socket = io.connect('http://' + document.domain + ':' + location.port);
    socket.on('new_packet', function(msg) {
        $('#data').append('<p>' + msg.data + '</p>');
    });
});
