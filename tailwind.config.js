/** @type {import('tailwindcss').Config} */
const Path = require("path");
const pwd = process.env.PWD;

const projectPaths = [
  Path.join(pwd, "./ezziee/templates/**/*.html"),
  Path.join(pwd, "../ezziee/templates/**/*.html"),
  Path.join(pwd, "../../ezziee/templates/**/*.html"),
  // add js file paths if you need
  // Path.join(pwd, "../node_modules/flowbite/**/*.js"),
];

const contentPaths = [...projectPaths];
const defaultTheme = require('tailwindcss/defaultTheme');


module.exports = {
  content: contentPaths,
  darkMode: 'class',
  theme: {
    extend: {
      screens: {
        xxs: '325px',
        ...defaultTheme.screens
      },
      fontSize: {
        xxs: '0.55rem',
        xs: "0.60rem",
        s: "0.65rem",
      },
      boxShadow: {
        '3xl': '0 -2px 5px 4px rgba(148,148,148,148.014)'
      },
      fontFamily: {
        'mus': ["'Museo Sans Rounded'", 'sans-serif'],
        "agbalumo": ["Agbalumo"],
        "quicksand": ["Quicksand"],
        "REM": ["REM"],
        "poppins": ["'Poppins'", "sans-serif"],
      },
      colors: {
        light: '#f0e4d5',
        dark: '#343541',
        primary: "#0F32A2",
        secondary: "#5AC5EC",
        debug: "#636363",
        warning: '#ffab2d',
        info: "#56A4EC",
        danger: '#FF0000',
        success: "#34A853",
      },
      keyframes: {
        wiggle: {
            '0%, 100%': { transform: 'rotate(-9deg)' },
            '50%': { transform: 'rotate(9deg)' },
        },
      },
      animation: {
        wiggle: 'wiggle 1s ease-in-out infinite',
        'wiggle-slow': 'wiggle 2s linear infinite',
        'ping-slow': 'ping 1s linear infinite',
        'ping-slower': 'ping 2s linear infinite',
        'spin-slow': 'spin 2s linear infinite',
        'spin-slower': 'spin 3s linear infinite',
        'bounce-slow': 'bounce 3s linear infinite',
      }
    },
  },
  variants: {
    extend: {},
    scrollBar: ["rounded"],
  },
  plugins: [
    require('@tailwindcss/typography'),
    require('@tailwindcss/forms'),
    require('@tailwindcss/line-clamp'),
    require('@tailwindcss/aspect-ratio'),
    require('tailwind-scrollbar-hide'),
    require('tailwind-scrollbar'),
    require("daisyui"),
  ],
  daisyui: {
    themes: false, // true: all themes | false: only light + dark | array: specific themes like this ["light", "dark", "cupcake"]
    base: true, // applies background color and foreground color for root element by default
    styled: true, // include daisyUI colors and design decisions for all components
    utils: true, // adds responsive and modifier utility classes
    rtl: false, // rotate style direction from left-to-right to right-to-left. You also need to add dir="rtl" to your html tag and install `tailwindcss-flip` plugin for Tailwind CSS.
    prefix: "", // prefix for daisyUI classnames (components, modifiers and responsive class names. Not colors)
    logs: true, // Shows info about daisyUI version and used config in the console when building your CSS
  },
}

