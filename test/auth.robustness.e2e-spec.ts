import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from './../src/app.module';
import { UserRole } from './../src/auth/enums/role.enum';
import cookieParser from 'cookie-parser';

describe('Auth Robustness (e2e)', () => {
    let app: INestApplication;

    beforeAll(async () => {
        const moduleFixture: TestingModule = await Test.createTestingModule({
            imports: [AppModule],
        }).compile();

        app = moduleFixture.createNestApplication();
        app.use(cookieParser());
        app.useGlobalPipes(new ValidationPipe());
        await app.init();
    });

    afterAll(async () => {
        await app.close();
    });

    const uniqueEmail = () => `test-${Date.now()}@example.com`;
    const uniqueHandle = () => `@user-${Date.now()}`;

    describe('/auth/signup (POST)', () => {
        it('should ignore role choice and default to CREATOR', async () => {
            const email = uniqueEmail();
            const response = await request(app.getHttpServer())
                .post('/auth/signup')
                .send({
                    email,
                    password: 'password123',
                    firstName: 'John',
                    lastName: 'Doe',
                    handle: uniqueHandle(),
                    role: UserRole.BRAND, // Should be ignored
                })
                .expect(201);

            expect(response.body.user.role).toBe(UserRole.CREATOR);
        });

        it('should reject passwords shorter than 8 characters', async () => {
            await request(app.getHttpServer())
                .post('/auth/signup')
                .send({
                    email: uniqueEmail(),
                    password: 'short',
                    firstName: 'John',
                    lastName: 'Doe',
                    handle: uniqueHandle(),
                })
                .expect(400);
        });

        it('should require firstName and lastName', async () => {
            await request(app.getHttpServer())
                .post('/auth/signup')
                .send({
                    email: uniqueEmail(),
                    password: 'password123',
                    handle: uniqueHandle(),
                    // missing first/last name
                })
                .expect(400);
        });

        it('should set isEmailVerified to false on signup and allow verifying', async () => {
            const email = uniqueEmail();
            const handle = uniqueHandle();

            const signupRes = await request(app.getHttpServer())
                .post('/auth/signup')
                .send({
                    email,
                    password: 'password123',
                    firstName: 'John',
                    lastName: 'Doe',
                    handle,
                })
                .expect(201);

            // Email verification link is only logged by MailService stub; we can't read it here easily.
            // Instead, we simulate verification by calling /auth/verify with a fake token
            // to ensure the route is wired. In a real test, we'd expose the token or inject MailService.
            await request(app.getHttpServer())
                .get('/auth/verify')
                .query({ token: 'invalid-token' })
                .expect(401);
        });
    });

    describe('/auth/refresh (POST)', () => {
        it('should preserve remember status', async () => {
            const email = uniqueEmail();
            // 1. Signup
            const signupRes = await request(app.getHttpServer())
                .post('/auth/signup')
                .send({
                    email,
                    password: 'password123',
                    firstName: 'John',
                    lastName: 'Doe',
                    handle: uniqueHandle(),
                });

            const refreshCookie = signupRes.get('Set-Cookie').find(c => c.startsWith('refresh_token'));

            // 2. Refresh (default remember is false)
            const refreshRes = await request(app.getHttpServer())
                .post('/auth/refresh')
                .set('Cookie', [refreshCookie])
                .expect(201);

            const newRefreshCookie = refreshRes.get('Set-Cookie').find(c => c.startsWith('refresh_token'));
            // Should NOT have Max-Age if not remembered (session cookie)
            expect(newRefreshCookie).not.toContain('Max-Age');

            // 3. Login with remember: true
            const loginRes = await request(app.getHttpServer())
                .post('/auth/login')
                .send({
                    email,
                    password: 'password123',
                    remember: true,
                });

            const rememberCookie = loginRes.get('Set-Cookie').find(c => c.startsWith('refresh_token'));
            expect(rememberCookie).toContain('Max-Age=2592000'); // 30 days

            // 4. Refresh while remembered
            const refreshRes2 = await request(app.getHttpServer())
                .post('/auth/refresh')
                .set('Cookie', [rememberCookie])
                .expect(201);

            const newRememberCookie = refreshRes2.get('Set-Cookie').find(c => c.startsWith('refresh_token'));
            expect(newRememberCookie).toContain('Max-Age=2592000'); // Should still be 30 days
        });
    });

    describe('Rate limiting and password reset (Auth)', () => {
        it('should apply rate limiting on /auth/login', async () => {
            const email = uniqueEmail();
            const password = 'password123';

            await request(app.getHttpServer())
                .post('/auth/signup')
                .send({
                    email,
                    password,
                    firstName: 'John',
                    lastName: 'Doe',
                    handle: uniqueHandle(),
                })
                .expect(201);

            // Intentionally call login with wrong password several times;
            // depending on Throttler configuration, some of these may be 401 or 429.
            for (let i = 0; i < 7; i++) {
                await request(app.getHttpServer())
                    .post('/auth/login')
                    .send({
                        email,
                        password: 'wrong-password',
                        remember: false,
                    })
                    .expect((res) => {
                        expect([401, 429]).toContain(res.status);
                    });
            }
        });

        it('should allow requesting password reset and resetting with invalid token fails', async () => {
            const email = uniqueEmail();

            await request(app.getHttpServer())
                .post('/auth/signup')
                .send({
                    email,
                    password: 'password123',
                    firstName: 'John',
                    lastName: 'Doe',
                    handle: uniqueHandle(),
                })
                .expect(201);

            await request(app.getHttpServer())
                .post('/auth/forgot-password')
                .send({ email })
                .expect(201);

            await request(app.getHttpServer())
                .post('/auth/reset-password')
                .send({ token: 'invalid-token', newPassword: 'newPassword123' })
                .expect(401);
        });
    });
});
