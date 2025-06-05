// Import required modules
const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const fs = require('fs').promises; // Use fs.promises for async file operations

// Initialize the Express application
const app = express();
const PORT = process.env.PORT || 3000;

// --- File Paths ---
const USERS_FILE_PATH = path.join(__dirname, 'users.json');
const TOURNAMENTS_FILE_PATH = path.join(__dirname, 'tournaments.json');
const GAMES_FILE_PATH = path.join(__dirname, 'games.json');

// --- In-memory Data Stores (loaded from files) ---
let users = [];
let tournaments = [];
let games = [];

// --- Helper Functions for Users ---
async function loadUsers() {
    try {
        const data = await fs.readFile(USERS_FILE_PATH, 'utf8');
        const parsedUsers = JSON.parse(data);
        // Ensure every user has a gamesList array
        users = parsedUsers.map(user => ({
            ...user,
            gamesList: Array.isArray(user.gamesList) ? user.gamesList : [] // Initialize if missing/invalid
        }));
        console.log('Users loaded and gamesList sanitized from users.json');
    } catch (error) {
        if (error.code === 'ENOENT') {
            users = [];
            console.log('users.json not found, starting empty.');
        } else {
            console.error('Error reading users.json:', error);
            users = []; // Default to empty on other errors
        }
    }
}

async function saveUsers() {
    try {
        await fs.writeFile(USERS_FILE_PATH, JSON.stringify(users, null, 2), 'utf8');
        console.log('Users saved to users.json');
    } catch (error) {
        console.error('Error writing users.json:', error);
    }
}

// --- Helper Functions for Tournaments ---
async function loadTournaments() {
    try {
        const data = await fs.readFile(TOURNAMENTS_FILE_PATH, 'utf8');
        let loadedTournaments = JSON.parse(data);
        
        // Ensure all tournaments have status, matches, and participants array
        tournaments = loadedTournaments.map(t => ({
            ...t,
            participants: Array.isArray(t.participants) ? t.participants : [], // Ensure participants is an array
            status: t.status || "pending", // Default to "pending" if status is missing
            matches: Array.isArray(t.matches) ? t.matches : [] // Default to an empty array if matches is missing or not an array
        }));
        console.log('Tournaments loaded, sanitized (status, matches, participants ensured) from tournaments.json');
    } catch (error) {
        if (error.code === 'ENOENT') {
            tournaments = [];
            console.log('tournaments.json not found, starting empty.');
        } else {
            console.error('Error reading tournaments.json:', error);
            tournaments = []; // Default to empty on other errors
        }
    }
}

async function saveTournaments() {
    try {
        await fs.writeFile(TOURNAMENTS_FILE_PATH, JSON.stringify(tournaments, null, 2), 'utf8');
        console.log('Tournaments saved to tournaments.json');
    } catch (error) {
        console.error('Error writing tournaments.json:', error);
    }
}

// --- Helper Functions for Games ---
async function loadGames() {
    try {
        const data = await fs.readFile(GAMES_FILE_PATH, 'utf8');
        games = JSON.parse(data);
        console.log('Games loaded from games.json');
    } catch (error) {
        if (error.code === 'ENOENT') {
            games = [];
            console.log('games.json not found, starting with default list.');
            games = [ // Default games list
                { id: '1', name: 'Valorant', genre: 'FPS', developer: 'Riot Games', description: 'A 5v5 character-based tactical shooter.', imageUrl: '/images/valorant.jpg' },
                { id: '2', name: 'League of Legends', genre: 'MOBA', developer: 'Riot Games', description: 'A fast-paced, competitive 5v5 strategic game.', imageUrl: '/images/leagueoflegends.jpg' },
                { id: '3', name: 'Counter-Strike 2', genre: 'Tactical Shooter', developer: 'Valve', description: 'The next era of Counter-Strike.', imageUrl: '/images/cs2.jpg' },
                { id: '4', name: 'Dota 2', genre: 'MOBA', developer: 'Valve', description: 'A complex 5v5 team-based strategy game.', imageUrl: '/images/dota2.jpg' }
            ];
            await saveGames();
        } else {
            console.error('Error reading games.json:', error);
            games = [];
        }
    }
}

async function saveGames() {
    try {
        await fs.writeFile(GAMES_FILE_PATH, JSON.stringify(games, null, 2), 'utf8');
        console.log('Games saved to games.json');
    } catch (error) {
        console.error('Error writing games.json:', error);
    }
}

// --- View Engine Setup ---
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// --- Middleware ---
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: false }));
app.use(session({
    store: new FileStore({
        path: './sessions',
        ttl: 86400, // 24 hours
        retries: 0
    }),
    secret: 'your super secret key for session signing', // Change this to a random string
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24, // 24 hours
        httpOnly: true
        // secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
    }
}));

app.use((req, res, next) => {
    res.locals.currentUser = req.session.user;
    next();
});

// --- General Routes ---
app.get('/', (req, res) => {
    res.render('index', { pageTitle: 'Tournament Hub' });
});

// --- Registration Routes ---
app.get('/register', (req, res) => {
    if (req.session.user) { return res.redirect('/profile'); }
    res.render('register', { pageTitle: 'Register' });
});

app.post('/register', async (req, res) => {
    try {
        if (req.session.user) { return res.redirect('/profile'); }
        const { username, email, password: plainTextPassword } = req.body;
        if (!username || !email || !plainTextPassword) {
            return res.status(400).render('register', { pageTitle: 'Register', error: 'All fields are required.' });
        }
        const existingUser = users.find(user => user.username === username || user.email === email);
        if (existingUser) {
            return res.status(400).render('register', { pageTitle: 'Register', error: 'Username or email already exists.' });
        }
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(plainTextPassword, saltRounds);
        const newUser = {
            id: Date.now().toString(),
            username,
            email,
            password: hashedPassword,
            gamesList: [] // Initialize with empty gamesList
        };
        users.push(newUser);
        await saveUsers();
        console.log('User registered and saved:', newUser);
        req.session.user = { id: newUser.id, username: newUser.username, email: newUser.email };

        req.session.save((err) => {
            if (err) {
                console.error('Error saving session after registration:', err);
                return res.status(500).render('register', { pageTitle: 'Register', error: 'Registration failed due to session error.' });
            }
            res.redirect('/profile');
        });

    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).render('register', { pageTitle: 'Register', error: 'An error occurred during registration.' });
    }
});

// --- Login Routes ---
app.get('/login', (req, res) => {
    if (req.session.user) { return res.redirect('/profile'); }
    res.render('login', { pageTitle: 'Login' });
});

app.post('/login', async (req, res) => {
    try {
        if (req.session.user) {
            console.log('Already logged in, redirecting to profile.');
            return res.redirect('/profile');
        }
        const { usernameOrEmail, password: plainTextPasswordAttempt } = req.body;
        if (!usernameOrEmail || !plainTextPasswordAttempt) {
            return res.status(400).render('login', { pageTitle: 'Login', error: 'Username/Email and password are required.' });
        }
        const user = users.find(u => u.username === usernameOrEmail || u.email === usernameOrEmail);
        if (!user) {
            return res.status(401).render('login', { pageTitle: 'Login', error: 'Invalid username/email or password.' });
        }
        const passwordsMatch = await bcrypt.compare(plainTextPasswordAttempt, user.password);
        if (passwordsMatch) {
            req.session.user = { id: user.id, username: user.username, email: user.email };
            console.log('Login successful, session created for:', req.session.user);
            console.log('--- Attempting to save session and redirect to /profile ---');

            req.session.save((err) => {
                if (err) {
                    console.error('Error saving session after login:', err);
                    return res.status(500).render('login', { pageTitle: 'Login', error: 'Login failed due to session error.' });
                }
                res.redirect('/profile');
            });

        } else {
            return res.status(401).render('login', { pageTitle: 'Login', error: 'Invalid username/email or password.' });
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).render('login', { pageTitle: 'Login', error: 'An error occurred during login.' });
    }
});

// --- Profile Page Route (Protected) ---
app.get('/profile', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    const fullUser = users.find(u => u.id === req.session.user.id);

    if (!fullUser) {
        // This case should ideally not happen if session is valid and user exists
        console.error(`User ID ${req.session.user.id} from session not found in users array.`);
        req.session.destroy(err => { // Destroy corrupted session
            if (err) console.error('Error destroying session:', err);
        });
        return res.redirect('/login');
    }
    
    // gamesList is now guaranteed to be an array by loadUsers
    const userGames = fullUser.gamesList.map(gameId => games.find(g => g.id === gameId)).filter(Boolean);
    const availableGames = games.filter(game => !fullUser.gamesList.includes(game.id));

    res.render('profile', {
        pageTitle: 'Your Profile',
        fullUser: fullUser,
        userGames: userGames,
        availableGames: availableGames
    });
});

// Handle adding a game to a user's games list
app.post('/profile/add-game', async (req, res) => {
    if (!req.session.user) {
        return res.status(403).send('You must be logged in to add games.');
    }

    const { gameId } = req.body;
    const userId = req.session.user.id;

    const userIndex = users.findIndex(u => u.id === userId);
    if (userIndex === -1) {
        return res.status(404).send('User not found.');
    }

    const gameToAdd = games.find(g => g.id === gameId);
    if (!gameToAdd) {
        return res.status(400).send('Game not found.');
    }

    // gamesList is guaranteed by loadUsers to be an array
    if (!users[userIndex].gamesList.includes(gameId)) {
        users[userIndex].gamesList.push(gameId);
        await saveUsers();
        console.log(`Game ${gameToAdd.name} added to ${users[userIndex].username}'s list.`);
    } else {
        console.log(`Game ${gameToAdd.name} already in ${users[userIndex].username}'s list.`);
    }

    const referer = req.get('Referer');
    res.redirect(referer || '/profile');
});

// Handle removing a game from a user's games list
app.post('/profile/remove-game', async (req, res) => {
    if (!req.session.user) {
        return res.status(403).send('You must be logged in to remove games.');
    }

    const { gameId } = req.body;
    const userId = req.session.user.id;

    const userIndex = users.findIndex(u => u.id === userId);
    if (userIndex === -1) {
        return res.status(404).send('User not found.');
    }

    const gameToRemove = games.find(g => g.id === gameId);
    
    // gamesList is guaranteed by loadUsers to be an array
    const initialLength = users[userIndex].gamesList.length;
    users[userIndex].gamesList = users[userIndex].gamesList.filter(id => id !== gameId);

    if (users[userIndex].gamesList.length < initialLength) {
        await saveUsers();
        console.log(`Game ${gameToRemove ? gameToRemove.name : 'Unknown Game'} removed from ${users[userIndex].username}'s list.`);
    } else {
        console.log(`Game ${gameToRemove ? gameToRemove.name : 'Unknown Game'} not found in ${users[userIndex].username}'s list.`);
    }

    const referer = req.get('Referer');
    res.redirect(referer || '/profile');
});

// --- Logout Route ---
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).send('Could not log out, please try again.');
        }
        console.log('Session destroyed, user logged out.');
        res.redirect('/');
    });
});

// --- Tournament Routes ---
// Display all tournaments
app.get('/tournaments', (req, res) => {
    console.log('--- Entering /tournaments route handler ---');
    // console.log('Value of tournaments at start of route:', tournaments); // Can be verbose
    console.log('Type of tournaments at start of route:', typeof tournaments);
    console.log('Is tournaments an array at start of route?', Array.isArray(tournaments));

    if (!Array.isArray(tournaments)) {
        console.error("CRITICAL ERROR: 'tournaments' is not an array in /tournaments route!");
        return res.status(500).render('error', { pageTitle: 'Error', message: 'Tournament data could not be loaded.' });
    }

    const tournamentsWithGameInfo = tournaments.map(t => { 
        const gameInfo = games.find(g => g.name === t.game);
        return {
            ...t,
            gameImageUrl: gameInfo ? gameInfo.imageUrl : '/images/default_game.jpg'
        };
    });

    // console.log('Successfully augmented tournaments. Rendering page.'); // Can be verbose
    res.render('tournaments/index', {
        pageTitle: 'All Tournaments',
        tournaments: tournamentsWithGameInfo
    });
});

// Display form to create a new tournament
app.get('/tournaments/new', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    res.render('tournaments/new', { pageTitle: 'Create New Tournament', games: games });
});

// Handle creation of a new tournament
app.post('/tournaments', async (req, res) => {
    if (!req.session.user) {
        return res.status(403).send('You must be logged in to create a tournament.');
    }
    try {
        const { name, game, description, date } = req.body;
        if (!name || !game || !description || !date) {
            return res.status(400).render('tournaments/new', {
                pageTitle: 'Create New Tournament',
                error: 'All fields are required.',
                games: games 
            });
        }

        const newTournament = {
            id: Date.now().toString(),
            name: name,
            game: game, 
            description: description,
            date: date,
            creatorId: req.session.user.id,
            creatorUsername: req.session.user.username,
            createdAt: new Date().toISOString(),
            participants: [], 
            status: "pending",  // <-- MODIFIED: Default status
            matches: []         // <-- MODIFIED: Initialize with an empty matches array
        };

        tournaments.push(newTournament);
        await saveTournaments();
        console.log('Tournament created:', newTournament);
        res.redirect('/tournaments');

    } catch (error) {
        console.error('Error creating tournament:', error);
        res.status(500).render('tournaments/new', {
            pageTitle: 'Create New Tournament',
            error: 'An error occurred while creating the tournament.',
            games: games
        });
    }
});

// Display a single tournament's details
app.get('/tournaments/:id', (req, res) => {
    const tournamentId = req.params.id;
    const tournament = tournaments.find(t => t.id === tournamentId);

    if (tournament) {
        const gameInfo = games.find(g => g.name === tournament.game);
        // Ensure participants is an array before mapping (already done by loadTournaments)
        const participantsFullInfo = tournament.participants.map(pId => users.find(u => u.id === pId)).filter(Boolean);

        res.render('tournaments/show', {
            pageTitle: tournament.name,
            tournament: tournament, // Will now include .status and .matches
            gameInfo: gameInfo,
            participantsFullInfo: participantsFullInfo,
            isParticipant: req.session.user ? tournament.participants.includes(req.session.user.id) : false
        });
    } else {
        console.log(`Tournament with ID ${tournamentId} not found for displaying details.`);
        res.status(404).render('404', {
            pageTitle: 'Tournament Not Found',
            message: 'The tournament you are looking for does not exist or could not be found.'
        });
    }
});

// Handle joining a tournament
app.post('/tournaments/:id/join', async (req, res) => {
    if (!req.session.user) {
        return res.status(403).send('You must be logged in to join a tournament.');
    }

    const tournamentId = req.params.id;
    const userId = req.session.user.id;
    const tournamentIndex = tournaments.findIndex(t => t.id === tournamentId);

    if (tournamentIndex === -1) {
        return res.status(404).send('Tournament not found.');
    }
    const tournament = tournaments[tournamentIndex];

    // participants array is guaranteed by loadTournaments
    if (tournament.participants.includes(userId)) {
        return res.redirect(`/tournaments/${tournamentId}?message=Already joined`);
    }
    if (tournament.status !== "pending") { // Only allow joining pending tournaments
        return res.redirect(`/tournaments/${tournamentId}?error=Tournament not accepting participants`);
    }

    tournament.participants.push(userId);
    await saveTournaments();
    console.log(`User ${req.session.user.username} joined tournament ${tournament.name}.`);
    res.redirect(`/tournaments/${tournamentId}`);
});

// Handle leaving a tournament
app.post('/tournaments/:id/leave', async (req, res) => {
    if (!req.session.user) {
        return res.status(403).send('You must be logged in to leave a tournament.');
    }

    const tournamentId = req.params.id;
    const userId = req.session.user.id;
    const tournamentIndex = tournaments.findIndex(t => t.id === tournamentId);

    if (tournamentIndex === -1) {
        return res.status(404).send('Tournament not found.');
    }
    const tournament = tournaments[tournamentIndex];

    // participants array is guaranteed by loadTournaments
    const initialParticipantsCount = tournament.participants.length;
    tournament.participants = tournament.participants.filter(pId => pId !== userId);

    if (tournament.participants.length < initialParticipantsCount) {
        await saveTournaments();
        console.log(`User ${req.session.user.username} left tournament ${tournament.name}.`);
    } else {
        console.log(`User ${req.session.user.username} was not found in tournament ${tournament.name}'s participants.`);
    }
    res.redirect(`/tournaments/${tournamentId}`);
});

// Display form to edit an existing tournament
app.get('/tournaments/:id/edit', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    const tournamentId = req.params.id;
    const tournament = tournaments.find(t => t.id === tournamentId);

    if (!tournament) {
        return res.status(404).render('404', { pageTitle: 'Not Found', message: 'Tournament not found.' });
    }
    if (req.session.user.id !== tournament.creatorId) {
        console.log(`Unauthorized attempt to edit tournament ${tournamentId}`);
        return res.status(403).render('403', { pageTitle: 'Access Denied', message: 'You are not authorized to edit this tournament.' });
    }
    if (tournament.status !== "pending") { // Only allow editing pending tournaments
         return res.status(403).render('403', { pageTitle: 'Cannot Edit', message: 'This tournament cannot be edited as it is not in a pending state.' });
    }

    res.render('tournaments/edit', {
        pageTitle: `Edit ${tournament.name}`,
        tournament: tournament,
        games: games
    });
});

// Handle update of an existing tournament
app.post('/tournaments/:id/edit', async (req, res) => {
    if (!req.session.user) {
        return res.status(403).send('You are not authorized.');
    }
    const tournamentId = req.params.id;
    const tournamentIndex = tournaments.findIndex(t => t.id === tournamentId);

    if (tournamentIndex === -1) {
        return res.status(404).render('404', { pageTitle: 'Not Found', message: 'The tournament you are trying to update does not exist.' });
    }
    const existingTournament = tournaments[tournamentIndex];

    if (req.session.user.id !== existingTournament.creatorId) {
        return res.status(403).render('403', { pageTitle: 'Access Denied', message: 'You are not authorized to update this tournament.' });
    }
    if (existingTournament.status !== "pending") {
         return res.status(403).render('403', { pageTitle: 'Cannot Edit', message: 'This tournament cannot be edited as it is not in a pending state.' });
    }

    try {
        const { name, game, description, date } = req.body;
        if (!name || !game || !description || !date) {
            return res.status(400).render('tournaments/edit', {
                pageTitle: `Edit ${existingTournament.name}`,
                tournament: existingTournament,
                error: 'All fields are required.',
                games: games
            });
        }

        tournaments[tournamentIndex] = {
            ...existingTournament,
            name,
            game,
            description,
            date
            // Status and matches remain untouched here, only core details are edited
        };
        await saveTournaments();
        console.log('Tournament updated:', tournaments[tournamentIndex]);
        res.redirect(`/tournaments/${tournamentId}`);

    } catch (error) {
        console.error('Error updating tournament:', error);
        res.status(500).render('tournaments/edit', {
            pageTitle: `Edit ${existingTournament.name}`,
            tournament: existingTournament,
            error: 'An error occurred while updating the tournament.',
            games: games
        });
    }
});

// Handle deletion of a tournament
app.post('/tournaments/:id/delete', async (req, res) => {
    if (!req.session.user) {
        return res.status(403).send('You are not authorized.');
    }
    const tournamentId = req.params.id;
    const tournamentIndex = tournaments.findIndex(t => t.id === tournamentId);

    if (tournamentIndex === -1) {
        return res.status(404).render('404', { pageTitle: 'Not Found', message: 'The tournament you are trying to delete does not exist.' });
    }
    const tournamentToDelete = tournaments[tournamentIndex];

    if (req.session.user.id !== tournamentToDelete.creatorId) {
        return res.status(403).render('403', { pageTitle: 'Access Denied', message: 'You are not authorized to delete this tournament.' });
    }
    // Optionally, only allow deletion if tournament is "pending"
    // if (tournamentToDelete.status !== "pending") {
    //     return res.status(403).render('403', { pageTitle: 'Cannot Delete', message: 'This tournament cannot be deleted as it is not in a pending state.' });
    // }

    try {
        tournaments.splice(tournamentIndex, 1);
        await saveTournaments();
        console.log('Tournament deleted:', tournamentToDelete);
        res.redirect('/tournaments');
    } catch (error) {
        console.error('Error deleting tournament:', error);
        res.redirect('/tournaments?error=deletion_failed');
    }
});


// --- Games Routes ---
// Display all games with search functionality
app.get('/games', (req, res) => {
    let gamesToDisplay = [...games]; 
    const searchTerm = req.query.search;

    // console.log(`[GET /games] Route entered. Session user: ${req.session.user ? req.session.user.username : 'None'}`); // Can be verbose

    if (searchTerm) {
        const searchWords = searchTerm.toLowerCase().split(/\s+/).filter(Boolean);
        gamesToDisplay = games.filter(game => {
            const gameSearchableText = (
                game.name + ' ' +
                game.genre + ' ' +
                (game.description || '') + ' ' +
                (game.developer || '')
            ).toLowerCase();
            return searchWords.every(word => gameSearchableText.includes(word));
        });
    }

    let userGames = [];
    let availableGames = [];
    let fullUser = null;

    if (req.session.user) {
        fullUser = users.find(u => u.id === req.session.user.id);
        // console.log(`[GET /games] User ${req.session.user.username} lookup in users array. Found:`, !!fullUser); // Can be verbose

        if (fullUser) {
            // console.log(`[GET /games] fullUser object for ${fullUser.username}:`, JSON.stringify(fullUser, null, 2)); // Can be very verbose
            // gamesList is now guaranteed to be an array by the updated loadUsers function
            // console.log(`[GET /games] typeof fullUser.gamesList for ${fullUser.username}:`, typeof fullUser.gamesList); // Can be verbose
            // console.log(`[GET /games] Array.isArray(fullUser.gamesList) for ${fullUser.username}:`, Array.isArray(fullUser.gamesList)); // Can be verbose
            // console.log(`[GET /games] fullUser.gamesList value for ${fullUser.username}:`, fullUser.gamesList); // Can be verbose

            // console.log(`[GET /games] fullUser.gamesList for ${fullUser.username} is an array (guaranteed by loadUsers), proceeding to map for userGames.`); // Can be verbose
            userGames = fullUser.gamesList.map(gameId => {
                const foundGame = games.find(g => g.id === gameId);
                return foundGame;
            }).filter(Boolean);

            // console.log(`[GET /games] fullUser.gamesList for ${fullUser.username} is an array, proceeding to filter for availableGames.`); // Can be verbose
            availableGames = games.filter(game => !fullUser.gamesList.includes(game.id));

        } else {
            console.warn(`[GET /games] User with ID ${req.session.user.id} exists in session but not found in users array. This could indicate data inconsistency.`);
            userGames = [];
            availableGames = [...gamesToDisplay];
        }
    } else {
        userGames = [];
        availableGames = [...gamesToDisplay];
    }
    
    // console.log(`[GET /games] Rendering games/index with ${gamesToDisplay.length} games to display.`); // Can be verbose
    res.render('games/index', {
        pageTitle: 'All Games',
        games: gamesToDisplay,
        searchTerm: searchTerm || '',
        currentUser: req.session.user,
        userGames: userGames,
        availableGames: availableGames,
        fullUser: fullUser
    });
});


// --- Start the Server ---
async function startServer() {
    try {
        await loadUsers();
        await loadGames();
        await loadTournaments(); 
        
        app.listen(PORT, () => {
            console.log(`Server is running on http://localhost:${PORT}`);
            console.log('Current users at startup:', users.length > 0 ? users.map(u => `${u.username} (gamesList: ${Array.isArray(u.gamesList) ? u.gamesList.length : 'N/A'})`).join(', ') : 'None');
            console.log('Current tournaments at startup:', tournaments.length > 0 ? tournaments.map(t => `${t.name} (status: ${t.status || 'N/A'}, matches: ${Array.isArray(t.matches) ? t.matches.length : 'N/A'})`).join(', ') : 'None');
            console.log('Current games at startup:', games.length > 0 ? games.map(g => g.name).join(', ') : 'None');
        });
    } catch (err) {
        console.error('Failed to start server due to data loading error:', err);
        process.exit(1); // Exit the process if critical data loading fails
    }
}

startServer();