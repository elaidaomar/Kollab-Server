const mysql = require('mysql2/promise');

async function check() {
    const connection = await mysql.createConnection({
        host: 'localhost',
        port: 3306,
        user: 'root',
        password: '',
        database: 'kollab_db'
    });

    const email = 'testbrand@test.com';
    const [users] = await connection.execute('SELECT id FROM users WHERE email = ?', [email]);
    const userId = users[0].id;

    const [brands] = await connection.execute('SELECT id FROM brand_profiles WHERE userId = ?', [userId]);
    const brandId = brands[0].id;

    const [campaigns] = await connection.execute('SELECT title, type, status, deadline FROM campaigns WHERE brandId = ?', [brandId]);

    console.log('User ID:', userId);
    console.log('Brand ID:', brandId);
    console.log('Campaign Count:', campaigns.length);
    console.log('First Campaign:', campaigns[0]);

    const [allCampaigns] = await connection.execute('SELECT COUNT(*) as count FROM campaigns');
    console.log('Total Campaigns in DB:', allCampaigns[0].count);

    await connection.end();
}

check().catch(console.error);
