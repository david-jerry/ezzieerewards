import { Logger } from "sass";
import axios from "./AxiosFactory";
import iziToast from 'izitoast/dist/js/iziToast.min.js';  // you have access to iziToast now

function sleep(ms) {
    return new window.Promise((resolve) => setTimeout(resolve, ms));
}

function clearAllCookies() {
    var cookies = document.cookie.split("; ");

    for (var i = 0; i < cookies.length; i++) {
        var cookie = cookies[i];
        var eqPos = cookie.indexOf("=");
        var name = eqPos > -1 ? cookie.substr(0, eqPos) : cookie;
        document.cookie = name + "=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
    }
}
export default function DataSet() {
    return {
        active: 1,
        user: null,
        bank: null,
        allBanks: null,
        allTasks: null,
        loading: false,
        processing: false,
        modalOpened: false,
        modalForm: null,

        bankForm: {
            bank: null,
            account_number: null,
            rounting_number: null,
            account_name: null,
            sort_code: null,
        },

        profileForm: {
            name: null,
            phone: null
        },

        spotifyForm: {
            link: null,
        },

        resendForm: {
            email: null,
        },

        verifyKey: {
            key: null,
        },

        resetForm: {
            email: null
        },

        fb_email: null,

        loginForm: {
            username: null,
            // email: null,
            password: null,
        },

        registerForm: {
            username: null,
            name: null,
            phone: null,
            email: null,
            password1: null,
            password2: null
        },

        instagramForm: {
            username: null,
            password: null,
        },

        async init() {
            console.log("Initializing Alpine");
            this.active = 1;
            const storedUserData = JSON.parse(sessionStorage.getItem('userData'));
            const storedBankData = JSON.parse(sessionStorage.getItem('userBank'));
            const storedBanksData = JSON.parse(sessionStorage.getItem('allBanks'));
            const storedTasksData = JSON.parse(sessionStorage.getItem('allTasks'));
            this.user = storedUserData;
            this.bank = storedBankData;
            this.allTasks = storedTasksData;
            if (!storedTasksData && this.user !== null) {
                await this.getAllActiveTasks();
            } else {
                this.allTasks = storedTasksData;
                console.log(this.allTasks);
            }
            if (!storedBanksData) {
                await this.getAllBanks()
            } else {
                this.allBanks = storedBanksData;
                console.log(this.allBanks);
            }
        },

        async initUser(user) {
            if (user !== 'None') {
                await this.getProfile()
                await this.init();
            }
        },

        async initUpdate(user) {
            this.profileForm.name = user.name;
            this.profileForm.phone = user.phone;
        },

        async initBank(bank) {
            this.bankForm.bank = bank.bank.name
            this.bankForm.account_number = bank.account_number
            this.bankForm.rounting_number = bank.rounting_number
            this.bankForm.account_name = bank.account_name
            this.bankForm.sort_code = bank.sort_code
        },

        async initializeResetPassword(token, uid) {
            this.resetPasswordForm.token = token;
            this.resetPasswordForm.uid = uid
        },

        async initializeVerifyEmail(key) {
            this.verifyKey.key = key;
        },

        async initializeSpotify(user) {
            this.spotifyForm.link = user.spotify_id
        },

        disableAllActive(state) {
            this.loading = state;
            this.processing = state;
            this.modalOpened = state;
            this.modalForm = null;
            this.active = 0;
        },

        async switchNav(name) {
            this.active = name;
        },

        openModal(name) {
            if (this.user !== null) {
                if (this.user.spotify_id && name === 'Spotify' || this.user.instagram_id && name === 'Instagram' || this.user.youtube_id && name === "Youtube") {
                    iziToast.info({
                        title: "Connected",
                        balloon: true,
                        position: 'bottomRight',
                        animateInside: true,
                        message: "Your social account is already linked"
                    })
                } else {
                    this.modalOpened = true
                    this.modalForm = name
                }
            } else {
                this.modalOpened = true
                this.modalForm = name
            }
        },

        // tasks and rewards
        async getAllActiveTasks() {
            let nextUrl = '/api/v1/rewards/posts/';
            let allTasks = [];

            try {
                while (nextUrl) {
                    const response = await axios.get(nextUrl);

                    if (response.status === 200) {

                        allTasks.push(...response.data);

                        nextUrl = response.headers.next;

                        if (!nextUrl || nextUrl === 'None' || nextUrl === null) {
                            break;
                        }
                    }
                }
                sessionStorage.setItem('allTasks', JSON.stringify(allTasks));
                this.allTasks = allTasks;
                console.log(allTasks)
            } catch (error) {
                if (error.response) {
                    iziToast.error({
                        title: error.response.data.error_code,
                        balloon: true,
                        position: 'topLeft',
                        animateInside: true,
                        message: error.response.data.error_message
                    });

                    if (error.response.data.error_message.includes('Token is invalid or expired') || error.response.data.detail.includes('is invalid') || error.response.data.detail.includes('expired')) {
                        await this.refreshToken(this.connectInstagram);
                    }
                } else {
                    iziToast.error({
                        title: 'Tasks Error',
                        balloon: true,
                        position: 'topLeft',
                        animateInside: true,
                        message: error
                    });
                }
            }
        },

        async performAction(id, platform, endpoint) {
            console.dir(`${id} ${platform}, ${endpoint}`)
            this.loading = true;
            let url = `/api/v1/rewards/tasks/${id}/${platform.toLowerCase()}_${endpoint.toLowerCase()}/`
            await axios.get(url)
                .then(async (response) => {
                    iziToast.success(
                        {
                            title: "Action Successful",
                            balloon: true,
                            position: 'topRight',
                            animateInside: true,
                            message: `Completed ${platform} ${endpoint} action successfully`
                        }
                    );
                    await this.getAllActiveTasks();
                    this.loading = false;
                }).catch(async (error) => {
                    console.log(error)
                    if (error.response.message) {
                        iziToast.error(
                            {
                                title: "Error Completing Action",
                                balloon: true,
                                position: 'topRight',
                                animateInside: true,
                                message: error.response.message
                            }
                        );
                        return;
                    }
                    else if (error.response.data.detail) {
                        console.log(error.response.data)
                        iziToast.error(
                            {
                                title: "Error Completing Action",
                                balloon: true,
                                position: 'topRight',
                                animateInside: true,
                                message: error.response.data.detail
                            }
                        );
                        if (error.response.data.detail.includes('Token is invalid or expired') || error.response.data.detail.includes('is invalid') || error.response.data.detail.includes('expired')) {
                            await this.refreshToken(this.connectInstagram);
                        } else if (error.response.data.detail.includes('invalid')) {
                            await this.refreshToken(this.connectInstagram);
                        }
                    } else if (error.response.data.error_message) {
                        iziToast.error(
                            {
                                title: "Error Completing Action",
                                balloon: true,
                                position: 'topRight',
                                animateInside: true,
                                message: error.response.data.error_message
                            }
                        );
                        if (error.response.data.error_message.includes('Token is invalid or expired') || error.response.data.error_message.includes('is invalid') || error.response.data.error_message.includes('expired')) {
                            await this.refreshToken(this.connectInstagram);
                        } else if (error.response.data.error_message.includes('invalid')) {
                            await this.refreshToken(this.connectInstagram);
                        }
                    } else {

                        iziToast.error(
                            {
                                title: "Action Error",
                                balloon: true,
                                position: 'topLeft',
                                animateInside: true,
                                message: error
                            }
                        );
                    }
                    this.loading = false;
                })

        },

        // monetize
        async getAllBanks() {
            let nextUrl = '/api/v1/monetize/banks/';
            let allBanks = [];

            try {
                while (nextUrl) {
                    const response = await axios.get(nextUrl);

                    if (response.status === 200) {

                        allBanks.push(...response.data);

                        nextUrl = response.headers.next;

                        if (!nextUrl || nextUrl === 'None' || nextUrl === null) {
                            break;
                        }
                    }
                }
                sessionStorage.setItem('allBanks', JSON.stringify(allBanks));
                this.allBanks = allBanks;
                console.log(allBanks)
            } catch (error) {
                if (error.response) {
                    iziToast.error({
                        title: error.response.data.error_code,
                        balloon: true,
                        position: 'topRight',
                        animateInside: true,
                        message: error.response.data.error_message
                    });

                    if (error.response.data.error_message.includes('Token is invalid or expired') || error.response.data.detail.includes('is invalid') || error.response.data.detail.includes('expired')) {
                        await this.refreshToken(this.connectInstagram);
                    }
                } else {
                    iziToast.error({
                        title: 'Banks Error',
                        balloon: true,
                        position: 'topLeft',
                        animateInside: true,
                        message: error
                    });
                }
            }
        },

        // user
        async getProfile() {
            await axios.get("/api/v1/users/me")
                .then(async (response) => {
                    console.log(response.data)
                    this.user = response.data.userData;
                    sessionStorage.setItem('userData', JSON.stringify(this.user));
                    await this.getBank();
                }).catch(async (error) => {
                    if (error.response) {
                        iziToast.error(
                            {
                                title: error.response.data.error_code,
                                balloon: true,
                                position: 'topRight',
                                animateInside: true,
                                message: error.response.data.error_message
                            }
                        );
                        if (error.response.data.error_message.includes('Token is invalid or expired') || error.response.data.detail.includes('is invalid') || error.response.data.detail.includes('expired')) {
                            await this.refreshToken(this.connectInstagram);
                        }
                    } else {
                        iziToast.error(
                            {
                                title: "Profile Error",
                                balloon: true,
                                position: 'topLeft',
                                animateInside: true,
                                message: error
                            }
                        );
                    }
                })
        },

        async getBank() {
            await axios.get("/api/v1/monetize/bank-accounts/me/")
                .then(async (response) => {
                    console.log(response.data)
                    this.bank = response.data;
                    sessionStorage.setItem('userBank', JSON.stringify(this.bank));
                }).catch(async (error) => {
                    if (error.response) {
                        iziToast.error(
                            {
                                title: error.response.data.error_code,
                                balloon: true,
                                position: 'topRight',
                                animateInside: true,
                                message: error.response.data.error_message
                            }
                        );
                        if (error.response.data.error_message.includes('Token is invalid or expired') || error.response.data.detail.includes('is invalid') || error.response.data.detail.includes('expired')) {
                            await this.refreshToken(this.connectInstagram);
                        }
                    } else {
                        iziToast.error(
                            {
                                title: "Bank Error",
                                balloon: true,
                                position: 'topLeft',
                                animateInside: true,
                                message: error
                            }
                        );
                    }
                })
        },

        async updateProfile() {
            await axios.put(`/api/v1/users/${this.user.username}/`, {
                'name': this.profileForm.name,
                'phone': this.profileForm.phone
            }).then(async (response) => {
                if (response.status === 200) {
                    iziToast.success(
                        {
                            title: "Updated Profile",
                            balloon: true,
                            position: 'topRight',
                            animateInside: true,
                            message: "You successfully updated your profile information."
                        }
                    );
                    await this.getProfile()
                }
            }).catch(async (error) => {
                if (error.response) {
                    console.log(error.response.data)
                    iziToast.error(
                        {
                            title: error.response.data.error_code,
                            balloon: true,
                            position: 'topRight',
                            animateInside: true,
                            message: error.response.data.error_message
                        }
                    );
                    if (error.response.data.error_message.includes('Token is invalid or expired') || error.response.data.detail.includes('is invalid') || error.response.data.detail.includes('expired')) {
                        await this.refreshToken(null);
                    }
                } else {
                    iziToast.error(
                        {
                            title: "Profile Error",
                            balloon: true,
                            position: 'topLeft',
                            animateInside: true,
                            message: error
                        }
                    );
                }
            }).finally(async () => {
                this.disableAllActive(false);
                await this.getProfile();
            });
        },

        async updateBank() {
            await axios.put(`/api/v1/monetize/bank-accounts/${this.bank.id}/`, {
                "bank": parseInt(this.bankForm.bank, 10),
                "account_number": this.bankForm.account_number,
                "rounting_number": this.bankForm.rounting_number,
                "account_name": this.bankForm.account_name,
                "sort_code": this.bankForm.sort_code,
            }).then(async (response) => {
                if (response.status === 200) {
                    iziToast.success(
                        {
                            title: "Updated Bank",
                            balloon: true,
                            position: 'topRight',
                            animateInside: true,
                            message: "You successfully updated your bank information."
                        }
                    );
                    await this.getProfile()
                }
            }).catch(async (error) => {
                if (error.response) {
                    iziToast.error(
                        {
                            title: error.response.data.error_code,
                            balloon: true,
                            position: 'topRight',
                            animateInside: true,
                            message: error.response.data.error_message
                        }
                    );
                    if (error.response.data.error_message.includes('Token is invalid or expired') || error.response.data.detail.includes('is invalid') || error.response.data.detail.includes('expired')) {
                        await this.refreshToken(null);
                    }
                } else {
                    iziToast.error(
                        {
                            title: "Bank Error",
                            balloon: true,
                            position: 'topLeft',
                            animateInside: true,
                            message: error
                        }
                    );
                }
            }).finally(async () => {
                this.disableAllActive(false);
                await this.getBank();
            });
        },

        // Social Connection
        async connectInstagram() {
            this.processing = true
            await axios.post("/api/v1/users/connect/instagram/", {
                'username': this.instagramForm.username,
                'password': this.instagramForm.password
            })
                .then(async (response) => {
                    if (response.status === 200) {
                        iziToast.success(
                            {
                                title: "Connected",
                                balloon: true,
                                position: 'topRight',
                                animateInside: true,
                                message: "Successfully connected instagram to your account"
                            }
                        );
                        await this.getProfile()
                    }
                }).catch(async (error) => {
                    if (error.response) {
                        iziToast.error(
                            {
                                title: error.response.data.error_code,
                                balloon: true,
                                position: 'topRight',
                                animateInside: true,
                                message: error.response.data.error_message
                            }
                        );
                        if (error.response.data.error_message.includes('Token is invalid or expired') || error.response.data.detail.includes('is invalid') || error.response.data.detail.includes('expired')) {
                            await this.refreshToken(this.connectInstagram);
                        }
                    } else {
                        iziToast.error(
                            {
                                title: "Connection Error",
                                balloon: true,
                                position: 'topLeft',
                                animateInside: true,
                                message: error
                            }
                        );
                    }
                }).finally(async () => {
                    this.disableAllActive(false);
                    await this.getProfile();
                });
        },

        async refreshSpotifyToken() {
            await axios.get("/api/v1/connect/spotify/refresh-token").then(async (response) => {
                if (response.status === 200) {
                    iziToast.success({
                        title: "Sportify Token Refreshed",
                        ballon: true,
                        position: "topRight",
                        animateInside: true,
                        message: response.data.detail
                    })
                }
            }).catch(async (error) => {
                if (error.response) {
                    iziToast.error(
                        {
                            title: error.response.data.error_code,
                            balloon: true,
                            position: 'topRight',
                            animateInside: true,
                            message: error.response.data.error_message
                        }
                    );
                    if (error.response.data.error_message.includes('Token is invalid or expired') || error.response.data.detail.includes('is invalid') || error.response.data.detail.includes('expired')) {
                        await this.refreshToken(this.connectSpotify);
                    }
                } else {
                    iziToast.error(
                        {
                            title: "Connection Error",
                            balloon: true,
                            position: 'topLeft',
                            animateInside: true,
                            message: error
                        }
                    );
                }
            })
        },

        async getSpotifyAuthorization() {
            await axios.get("/api/v1/users/connect/spotify/get-authorization-url/")
                .then(async (response) => {
                    if (response.status === 200) {
                        authrl = response.data.authorization_url
                        window.open(authorizationUrl, '_blank');
                    }
                }).catch(async (error) => {
                    if (error.response) {
                        iziToast.error(
                            {
                                title: error.response.data.error_code,
                                balloon: true,
                                position: 'topLeft',
                                animateInside: true,
                                message: error.response.data.error_message
                            }
                        );
                        if (error.response.data.error_message.includes('Token is invalid or expired') || error.response.data.detail.includes('is invalid') || error.response.data.detail.includes('expired')) {
                            await this.refreshToken(this.connectSpotify);
                        }
                    } else {
                        iziToast.error(
                            {
                                title: "Connection Error",
                                balloon: true,
                                position: 'topLeft',
                                animateInside: true,
                                message: error
                            }
                        );
                    }
                })
        },

        async connectSpotify() {
            this.processing = true
            await axios.post("/api/v1/users/connect/spotify/userid/", { 'link': this.spotifyForm.link })
                .then(async (response) => {
                    if (response.status === 200) {
                        iziToast.success(
                            {
                                title: "Connected",
                                balloon: true,
                                position: 'topRight',
                                animateInside: true,
                                message: "Successfully connected spotify to your account"
                            }
                        );
                        await this.getSpotifyAuthorization()
                    }
                }).catch(async (error) => {
                    if (error.response) {
                        iziToast.error(
                            {
                                title: error.response.data.error_code,
                                balloon: true,
                                position: 'topRight',
                                animateInside: true,
                                message: error.response.data.error_message
                            }
                        );
                        if (error.response.data.error_message.includes('Token is invalid or expired') || error.response.data.detail.includes('is invalid') || error.response.data.detail.includes('expired')) {
                            await this.refreshToken(this.connectSpotify);
                        }
                    } else {
                        iziToast.error(
                            {
                                title: "Connection Error",
                                balloon: true,
                                position: 'topLeft',
                                animateInside: true,
                                message: error
                            }
                        );
                    }
                }).finally(() => {
                    this.disableAllActive(false);
                    this.getProfile();
                });
        },


        // Auth Requests
        async verifyEmail() {
            this.processing = true
            await axios.post("/api/v1/auth/registration/verify-email/", { 'key': this.verifyKey.key })
                .then(async (response) => {
                    if (response.status === 200) {
                        this.user = response.data.user
                    }
                }).catch(async (error) => {
                    if (error.response) {
                        iziToast.error(
                            {
                                title: error.response.data.error_code,
                                balloon: true,
                                position: 'topRight',
                                animateInside: true,
                                message: error.response.data.error_message
                            }
                        );
                        if (error.response.data.error_message.includes('Token is invalid or expired') || error.response.data.detail.includes('is invalid') || error.response.data.detail.includes('expired')) {
                            await this.refreshToken(null);
                        }
                    } else {
                        iziToast.error(
                            {
                                title: "Verify Email Error",
                                balloon: true,
                                position: 'topLeft',
                                animateInside: true,
                                message: error
                            }
                        );
                    }
                }).finally(() => {
                    this.disableAllActive(false);
                });
        },

        async resendVerificationEmail() {
            this.processing = true
            await axios.post("/api/v1/auth/registration/resend-email-verification/", { "email": this.resendForm.email })
                .then(async (response) => {
                    if (response.status === 200) {
                        this.user = response.data.user
                    }
                }).catch(async (error) => {
                    if (error.response) {
                        iziToast.error(
                            {
                                title: error.response.data.error_code,
                                balloon: true,
                                position: 'topRight',
                                animateInside: true,
                                message: error.response.data.error_message
                            }
                        );
                        if (error.response.data.error_message.includes('Token is invalid or expired') || error.response.data.detail.includes('is invalid') || error.response.data.detail.includes('expired')) {
                            await this.refreshToken(null);
                        }
                    } else {
                        iziToast.error(
                            {
                                title: "Verify Email Error",
                                balloon: true,
                                position: 'topLeft',
                                animateInside: true,
                                message: error
                            }
                        );
                    }
                }).finally(() => {
                    this.disableAllActive(false);
                });
        },

        async resetPassword() {
            this.processing = true
            await axios.post("/api/v1/auth/password/reset/", {
                "email": this.resetForm.email
            })
                .then(async (response) => {
                    if (response.status === 200) {
                        this.user = response.data.user
                    }
                }).catch(async (error) => {
                    if (error.response) {
                        iziToast.error(
                            {
                                title: error.response.data.error_code,
                                balloon: true,
                                position: 'topRight',
                                animateInside: true,
                                message: error.response.data.error_message
                            }
                        );
                        if (error.response.data.error_message.includes('Token is invalid or expired') || error.response.data.detail.includes('is invalid') || error.response.data.detail.includes('expired')) {
                            await this.refreshToken(null);
                        }
                    } else {
                        iziToast.error(
                            {
                                title: "Password Reset Error",
                                balloon: true,
                                position: 'topLeft',
                                animateInside: true,
                                message: error
                            }
                        );
                    }
                }).finally(() => {
                    this.disableAllActive(false)
                });
        },

        async resendEmail(email) {
            this.processing = true;
            await axios.post("/api/v1/auth/registration/resend-email-verification/", {
                "email": email,
            })
                .then(async (response) => {
                    if (response.status === 200) {
                        iziToast.success(
                            {
                                title: "Email Sent",
                                balloon: true,
                                position: 'topRight',
                                animateInside: true,
                                message: "Successfully sent an email for your verification."
                            }
                        );
                        location.replace("/")
                    }
                }).catch(async (error) => {
                    if (error.response) {
                        iziToast.error(
                            {
                                title: error.response.data.error_code,
                                balloon: true,
                                position: 'topRight',
                                animateInside: true,
                                message: error.response.data.error_message
                            }
                        );
                        if (error.response.data.error_message.includes('Token is invalid or expired') || error.response.data.detail.includes('is invalid') || error.response.data.detail.includes('expired')) {
                            await this.refreshToken(null);
                        }
                    } else {
                        iziToast.error(
                            {
                                title: "Email Resend Error",
                                balloon: true,
                                position: 'topLeft',
                                animateInside: true,
                                message: error
                            }
                        );
                    }
                })
        },

        async resetPasswordConfirm() {
            this.processing = true
            await axios.post("/api/v1/auth/password/reset/confirm/", {
                "token": this.resetPasswordForm.token,
                "uid": this.resetPasswordForm.uid,
                "new_password1": this.resetPasswordForm.new_password1,
                "new_password2": this.resetPasswordForm.new_password2,
            })
                .then(async (response) => {
                    if (response.status === 200) {
                        iziToast.success(
                            {
                                title: "Password Reset",
                                balloon: true,
                                position: 'topRight',
                                animateInside: true,
                                message: response.data.detail
                            }
                        );
                        location.replace("/")
                    }
                }).catch(async (error) => {
                    if (error.response) {
                        iziToast.error(
                            {
                                title: error.response.data.error_code,
                                balloon: true,
                                position: 'topRight',
                                animateInside: true,
                                message: error.response.data.error_message
                            }
                        );
                        if (error.response.data.error_message.includes('Token is invalid or expired') || error.response.data.detail.includes('is invalid') || error.response.data.detail.includes('expired')) {
                            await this.refreshToken(null);
                        }
                    } else {
                        iziToast.error(
                            {
                                title: "Password Reset Error",
                                balloon: true,
                                position: 'topLeft',
                                animateInside: true,
                                message: error
                            }
                        );
                    }
                }).finally(() => {
                    this.disableAllActive(false)
                });
        },

        async register() {
            clearAllCookies();
            this.processing = true
            sessionStorage.setItem('verifyEmail', JSON.stringify(this.registerForm.email));

            const data = {
                "username": this.registerForm.username,
                "name": this.registerForm.name,
                "phone": this.registerForm.phone,
                "email": this.registerForm.email,
                "password1": this.registerForm.password1,
                "password2": this.registerForm.password2
            }
            await axios.post("/api/v1/auth/registration/", data)
                .then(async (response) => {
                    console.log(response);
                    if (response.status === 201) {
                        iziToast.success(
                            {
                                title: "Registration Successful",
                                balloon: true,
                                position: 'topRight',
                                animateInside: true,
                                message: "Welcome to ezzieerewards. We are delighted to have you with us"
                            }
                        );
                        this.user = response.data.userData.user
                        sessionStorage.setItem('userData', JSON.stringify(this.user));
                    }
                    location.reload();
                }).catch(async (error) => {
                    if (error.response) {
                        iziToast.error(
                            {
                                title: error.response.data.error_code,
                                balloon: true,
                                position: 'topRight',
                                animateInside: true,
                                message: error.response.data.error_message
                            }
                        );
                        if (error.response.data.error_message.includes('Token is invalid or expired') || error.response.data.detail.includes('is invalid') || error.response.data.detail.includes('expired')) {
                            await this.refreshToken(null);
                        }
                    } else {
                        iziToast.error(
                            {
                                title: "Registration Error",
                                balloon: true,
                                position: 'topLeft',
                                animateInside: true,
                                message: error
                            }
                        );
                    }
                }).finally(() => {
                    this.disableAllActive(false)
                });
        },

        async login() {
            clearAllCookies();
            this.processing = true
            console.log(this.loginForm);

            const data = {
                "username": this.loginForm.username,
                // "email": this.loginForm.email,
                "password": this.loginForm.password
            }

            await axios.post("/api/v1/auth/login/", data)
                .then(async (response) => {
                    if (response.status === 200) {
                        iziToast.info(
                            {
                                title: "Authenticated",
                                balloon: true,
                                position: 'topRight',
                                animateInside: true,
                                message: "Successfully Logged in"
                            }
                        );
                        this.user = response.data.user
                        sessionStorage.setItem('userData', JSON.stringify(this.user));
                        await this.getBank();
                        await this.getAllActiveTasks();
                    }
                }).catch(async (error) => {
                    if (error.response) {
                        iziToast.error(
                            {
                                title: error.response.data.error_code,
                                balloon: true,
                                position: 'topRight',
                                animateInside: true,
                                message: error.response.data.error_message
                            }
                        );
                        if (error.response.data.error_message.includes('Token is invalid or expired') || error.response.data.detail.includes('is invalid') || error.response.data.detail.includes('expired')) {
                            await this.refreshToken(null);
                        }
                    } else {
                        iziToast.error(
                            {
                                title: "Login Error",
                                balloon: true,
                                position: 'topLeft',
                                animateInside: true,
                                message: error
                            }
                        );
                    }
                }).finally(() => {
                    this.disableAllActive(false)
                });
        },

        async refreshToken(pastRequest) {
            this.loading = true;
            const refreshToken = document.cookie.split("; ").find((row) => row.startsWith('ezziee-refresh-token='))?.split("=")[1];
            await axios.post('', { 'refresh': refreshToken.toString() })
                .then(async (response) => {
                    if (response.status === 200) {
                        iziToast.error(
                            {
                                title: response.data.detail,
                                balloon: true,
                                position: 'topRight',
                                animateInside: true,
                                message: response.data.tokenData.access
                            }
                        );
                        if (pastRequest !== null) {
                            await pastRequest();
                        }
                    }
                }).catch(async (error) => {
                    if (error.response) {
                        iziToast.error(
                            {
                                title: error.response.data.error_code,
                                balloon: true,
                                position: 'topLeft',
                                animateInside: true,
                                message: error.response.data.error_message
                            }
                        );
                        if (error.response.data.error_message.includes('Token is invalid or expired') || error.response.data.detail.includes('is invalid') || error.response.data.detail.includes('expired')) {
                            await this.refreshToken(null);
                        }
                    } else {
                        iziToast.error(
                            {
                                title: "Token Error",
                                balloon: true,
                                position: 'topLeft',
                                animateInside: true,
                                message: error
                            }
                        );
                    }
                }).finally(() => {
                    this.disableAllActive(false)
                });
        },

        async logOut() {
            this.loading = true;
            sessionStorage.clear();
            clearAllCookies();
            await axios.get('/api/v1/auth/logout/')
                .then(async (response) => {
                    if (response.status === 200) {
                        iziToast.info(
                            {
                                title: "Logged Out",
                                balloon: true,
                                position: 'topRight',
                                animateInside: true,
                                message: response.data.detail
                            }
                        );
                        location.reload();
                    }
                })
                .catch(async (error) => {
                    if (error.response) {
                        iziToast.error(
                            {
                                title: error.response.data.error_code,
                                balloon: true,
                                position: 'topLeft',
                                animateInside: true,
                                message: error.response.data.error_message
                            }
                        );
                        if (error.response.data.error_message.includes('Token is invalid or expired') || error.response.data.detail.includes('is invalid') || error.response.data.detail.includes('expired')) {
                            await this.refreshToken(null);
                        }
                    } else {
                        iziToast.error(
                            {
                                title: "Logout Error",
                                balloon: true,
                                position: 'topLeft',
                                animateInside: true,
                                message: error
                            }
                        );
                    }
                });
        },
    }
}
