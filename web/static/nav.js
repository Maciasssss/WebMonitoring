$(document).ready(function() {
    const $burger = $('.burger');
    const $navLinks = $('.nav-links');
    const $body = $('body');
    $('body').addClass('no-scroll');
    function initBurgerMenu() {
        // Enable burger menu and event listeners for small screens
        if ($(window).width() <= 768) {
            // Ensure the burger is visible in mobile view
            $burger.show();

            $burger.off('click').on('click', function() {
                $navLinks.toggleClass('nav-active');
                $burger.toggleClass('toggle');
                $body.toggleClass('no-scroll');
            });

            $navLinks.find('li').off('click').on('click', function() {
                $navLinks.removeClass('nav-active');
                $burger.removeClass('toggle');
                $body.removeClass('no-scroll');
            });
        } else {
            // Reset for larger screens
            $burger.hide();
            $navLinks.removeClass('nav-active');
            $burger.removeClass('toggle');
            $body.removeClass('no-scroll');
        }
    }

    // Initialize the burger menu on page load
    initBurgerMenu();

    // Reapply the burger menu behavior when resizing the window
    $(window).on('resize', function() {
        initBurgerMenu();
    });
});

