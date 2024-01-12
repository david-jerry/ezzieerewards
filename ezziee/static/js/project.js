import '../sass/project.scss';
import "izitoast/dist/css/iziToast.min.css";



[
    "load",
].forEach((evt) => {
    window.addEventListener(evt, function () {
        const counters = document.querySelectorAll(".counter");
        const car = document.getElementById("car");

        const controller = new ScrollMagic.Controller();

        if (document.getElementById('const')) {
            lottieweb.loadAnimation({
                container: document.getElementById('const'),
                path: "/static/vendors/images/lottie/under-construction.json",
                renderer: 'svg',
                loop: true,
                autoPlay: true,
                name: 'Under Construction'
            });
        }

        function startCounting() {
            if (counters) {
                counters.forEach((counter) => {
                    anime({
                        targets: counter,
                        innerHTML: [0, counter.getAttribute("data-count")],
                        easing: "easeInOutSine",
                        round: 1,
                        duration: 4000,
                    });
                });
            }
        }

        function animateHows() {
            if (document.querySelectorAll(".how")) {
                anime({
                    targets: ".how",
                    translateX: 56,
                    easing: "easeInOutSine",
                    duration: 800,
                    opacity: 1,
                    delay: anime.stagger(200, { start: 500 }),
                });
            }
        }

        if (document.getElementById("countTrigger")) {
            new ScrollMagic.Scene({
                triggerElement: "#countTrigger",
                triggerHook: "onEnter",
                duration: "100%",
                reverse: false,
                offset: 50,
            })
                .on("enter", function () {
                    startCounting();
                })
                .addTo(controller);
        }

        if (document.getElementById("track")) {
            new ScrollMagic.Scene({
                triggerElement: "#track",
                triggerHook: "onEnter",
                duration: "100%",
                reverse: true,
                offset: 50,
            })
                .on("enter", function () {
                    carDrive();
                })
                .addTo(controller);
        }

        if (document.getElementById("hows")) {
            new ScrollMagic.Scene({
                triggerElement: "#hows",
                triggerHook: "onEnter",
                duration: "100%",
                reverse: false,
                offset: 100,
            })
                .on("enter", function () {
                    animateHows();
                })
                .addTo(controller);
        }

        if (document.querySelectorAll(".intro")) {
            anime({
                targets: ".intro",
                translateX: -56,
                easing: "easeInOutSine",
                duration: 800,
                opacity: 1,
                delay: anime.stagger(200, { start: 500 }),
            });
        }

        function carDrive() {
            if (car) {
                anime({
                    targets: "#car",
                    translateX: {
                        value: "-100vw",
                        duration: 5000,
                    },
                    easing: "easeInOutSine",
                    opacity: 1,
                    delay: anime.stagger(200, { start: 500 }),
                    direction: "normal",
                    loop: false,
                });
            }
        }
    });
});
