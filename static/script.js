const { createApp } = Vue

const app = createApp({
    delimiters: ['[[', ']]'],
    data() {
        return {
            showRegister: false,
            isLoggedIn: false,
            isAdmin: false,
            username: '',
            users: [],
            files: [],
            loginForm: {
                username: '',
                password: ''
            },
            registerForm: {
                username: '',
                password: ''
            }
        }
    },
    mounted() {
        // Check if user is already logged in
        const token = localStorage.getItem('token')
        if (token) {
            this.getUserInfo()
            this.getFiles()
        }
    },
    methods: {
        formatFileSize(bytes) {
            if (!bytes) return '0 B'
            const sizes = ['B', 'KB', 'MB', 'GB']
            const i = Math.floor(Math.log(bytes) / Math.log(1024))
            return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`
        },
        formatDate(dateString) {
            if (!dateString) return 'N/A'
            return new Date(dateString).toLocaleString()
        },
        async login() {
            try {
                const formData = new FormData()
                formData.append('username', this.loginForm.username)
                formData.append('password', this.loginForm.password)

                const response = await axios.post('http://localhost:8001/token', formData)
                localStorage.setItem('token', response.data.access_token)
                await this.getUserInfo()
                this.isLoggedIn = true
                this.getFiles()
            } catch (error) {
                console.error('Login error:', error)
                alert('Login failed. Please check your credentials.')
            }
        },
        async register() {
            try {
                await axios.post('http://localhost:8001/register', {
                    username: this.registerForm.username,
                    password: this.registerForm.password
                })
                this.showRegister = false
                alert('Registration successful! Please login.')
            } catch (error) {
                console.error('Registration error:', error)
                alert('Registration failed. Please try again.')
            }
        },
        async getUserInfo() {
            try {
                const token = localStorage.getItem('token')
                const response = await axios.get('http://localhost:8001/users/me', {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                })
                this.username = response.data.username
                this.isAdmin = response.data.is_admin
                this.isLoggedIn = true
                if (this.isAdmin) {
                    this.getAllUsers()
                }
            } catch (error) {
                console.error('Error fetching user info:', error)
                this.logout()
            }
        },
        async getFiles() {
            try {
                const token = localStorage.getItem('token')
                const response = await axios.get('http://localhost:8001/files', {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                })
                this.files = response.data
            } catch (error) {
                console.error('Error fetching files:', error)
            }
        },
        async getAllUsers() {
            try {
                const token = localStorage.getItem('token')
                const response = await axios.get('http://localhost:8001/admin/users', {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                })
                this.users = response.data
            } catch (error) {
                console.error('Error fetching users:', error)
            }
        },
        async makeAdmin(userId) {
            try {
                const token = localStorage.getItem('token')
                await axios.post(`http://localhost:8001/admin/make-admin/${userId}`, {}, {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                })
                alert('User has been made admin successfully')
                this.getAllUsers()
            } catch (error) {
                console.error('Error making user admin:', error)
                alert('Failed to make user admin')
            }
        },
        logout() {
            localStorage.removeItem('token')
            this.isLoggedIn = false
            this.isAdmin = false
            this.username = ''
            this.users = []
            this.files = []
            this.loginForm.username = ''
            this.loginForm.password = ''
        }
    }
})

app.mount('#app')
