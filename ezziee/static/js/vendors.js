// import Glide, { Controls, Breakpoints } from '@glidejs/glide/dist/glide.modular.esm'
// new Glide('.glide').mount({ Controls, Breakpoints })


import anime from 'animejs/lib/anime.es.js';
import Alpine from "alpinejs";
import htmx from "htmx.org/dist/htmx";
import "intl-tel-input/build/css/intlTelInput.css";
import ScrollMagic from "scrollmagic";

window.anime = anime;
window.ScrollMagic = ScrollMagic;

// initialize htmx
window.htmx = htmx;

// initialize alpine
import DataSet from "./components/DataSet"

window.Alpine = Alpine;
Alpine.data("Global", DataSet);
Alpine.start();
