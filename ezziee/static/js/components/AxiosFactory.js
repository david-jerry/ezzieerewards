import axios from "axios";


axios.defaults.withCredentials = true;
axios.defaults.xsrfCookieName = 'csrftoken';
axios.defaults.xsrfHeaderName = "X-CSRFTOKEN";
axios.defaults.timeout = 25000;

// Intercept the request to include the Django REST Auth token
// Intercept the request to include the Django REST Auth token
axios.interceptors.request.use(
    (config) => {
        // Check if the Django REST Auth token is available in the cookies
        const djangoAuthToken = document.cookie
            .split("; ")
            .find((row) => row.startsWith('ezziee-token='))
            ?.split("=")[1];

        // Include the Django REST Auth token in the request header
        if (djangoAuthToken) {
            config.headers.Authorization = `Bearer ${djangoAuthToken}`;
        }

        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

export default axios;
