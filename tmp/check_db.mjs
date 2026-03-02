import mysql from 'mysql2/promise';

async function check() {
    const connection = await mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: '',
        database: 'kollab_db'
    });

    try {
        const [campaigns] = await connection.query('SELECT id, brandId FROM campaigns');
        console.log(`Campaigns in DB: ${campaigns.length}`);
        for (const c of campaigns) {
            const [users] = await connection.query('SELECT id FROM users WHERE id = ?', [c.brandId]);
            if (users.length === 0) {
                console.log(`Campaign ${c.id} has invalid brandId ${c.brandId}`);
            }
        }

        const [applications] = await connection.query('SELECT id, creatorId FROM applications');
        console.log(`Applications in DB: ${applications.length}`);
        for (const a of applications) {
            const [users] = await connection.query('SELECT id FROM users WHERE id = ?', [a.creatorId]);
            if (users.length === 0) {
                console.log(`Application ${a.id} has invalid creatorId ${a.creatorId}`);
            }
        }
    } finally {
        await connection.end();
    }
}

check();
