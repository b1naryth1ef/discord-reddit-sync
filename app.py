from flask import Flask, session, redirect, request, url_for, render_template, flash
from requests_oauthlib import OAuth2Session
import settings
import praw
import os

PROVIDERS = ['discord', 'reddit']
FLAIR_COLORS = ['discord', 'green', 'red', 'orange', 'cyan', 'blue', 'purple']

app = Flask(__name__)
app.config.update({k: getattr(settings, k) for k in dir(settings)})
app.debug = app.config.get('DEBUG', False)
app.r = praw.Reddit(user_agent='Discord Reddit Syncer')
app.r.login(app.config['REDDIT_USERNAME'], app.config['REDDIT_PASSWORD'], disable_warning=True)


def token_updater_discord(token):
    session['discord_token'] = token


def token_updater_reddit(token):
    session['reddit_token'] = token


def make_discord_session(token=None, state=None, scope=None):
    return OAuth2Session(
        client_id=app.config['DISCORD_CLIENT_ID'],
        token=token,
        state=state,
        scope=scope,
        redirect_uri=app.config['DISCORD_REDIRECT_URI'],
        auto_refresh_kwargs={
            'client_id': app.config['DISCORD_CLIENT_ID'],
            'client_secret': app.config['DISCORD_CLIENT_SECRET'],
        },
        auto_refresh_url=app.config['DISCORD_TOKEN_URL'],
        token_updater=token_updater_discord)


def make_reddit_session(token=None, state=None, scope=None):
    return OAuth2Session(
        client_id=app.config['REDDIT_CLIENT_ID'],
        token=token,
        state=state,
        scope=scope,
        redirect_uri=app.config['REDDIT_REDIRECT_URI'],
        auto_refresh_kwargs={
            'client_id': app.config['REDDIT_CLIENT_ID'],
            'client_secret': app.config['REDDIT_CLIENT_SECRET'],
        },
        auto_refresh_url=app.config['REDDIT_TOKEN_URL'],
        token_updater=token_updater_reddit)


@app.route('/')
def route_index():
    return render_template('index.html', reddit=session.get('reddit'), discord=session.get('discord'), colors=FLAIR_COLORS)


@app.route('/logout/<provider>')
def route_logout(provider=None):
    if provider not in PROVIDERS:
        return 'Invalid Provider', 400

    if provider in session:
        del session[provider]
        del session[provider + '_token']

    flash('Logged out of %s' % provider, 'success')
    return redirect(url_for('.route_index'))


@app.route('/redirect/<provider>')
def route_redirect(provider=None):
    if provider == 'discord':
        discord = make_discord_session(scope=('identify', ))
        authorization_url, state = discord.authorization_url(app.config['DISCORD_AUTH_URL'])
        session['discord_state'] = state
    elif provider == 'reddit':
        reddit = make_reddit_session(scope=('identity', ))
        authorization_url, state = reddit.authorization_url(app.config['REDDIT_AUTH_URL'])
        authorization_url += '&duration=permanent'
        session['reddit_state'] = state
    else:
        return 'Invalid Provider', 400

    return redirect(authorization_url)


@app.route('/callback/<provider>')
def callback(provider=None):
    # Make sure this is a valid provider
    if provider not in PROVIDERS:
        return 'Invalid Provider', 400

    if request.values.get('error'):
        flash('Error logging into %s: %s' % (provider, request.values['error']), 'error')

    elif provider == 'discord':
        discord = make_discord_session(state=session.get('discord_state'))

        token = discord.fetch_token(
            app.config['DISCORD_TOKEN_URL'],
            client_secret=app.config['DISCORD_CLIENT_SECRET'],
            authorization_response=request.url)
        session['discord_token'] = token
        session['discord'] = get_discord_account()

        flash('Logged into Discord account %s' % session['discord']['username'], 'success')

    elif provider == 'reddit':
        reddit = make_reddit_session(state=session.get('reddit_state'))

        token = reddit.fetch_token(
            app.config['REDDIT_TOKEN_URL'],
            code=request.values['code'],
            client_id=app.config['REDDIT_CLIENT_ID'],
            client_secret=app.config['REDDIT_CLIENT_SECRET'],
            scope=('identity', ),
            state=session.get('reddit_state'),
            auth=(app.config['REDDIT_CLIENT_ID'], app.config['REDDIT_CLIENT_SECRET']),
            headers={
                'User-Agent': 'Discord Reddit Syncer',
            },
            duration='permanent',
            authorization_response=request.url)

        session['reddit_token'] = token
        session['reddit'] = get_reddit_account()

        flash('Logged into Reddit account %s' % session['reddit']['name'], 'success')

    return redirect(url_for('.route_index'))


@app.route('/link')
def link():
    flair_class = request.values.get('color', 'discord')
    if flair_class not in FLAIR_COLORS:
        return 'Invalid Flair Color', 400

    for provider in PROVIDERS:
        if provider + '_token' not in session:
            return 'Invalid Provider Session', 400

    session['reddit'] = get_reddit_account()
    session['discord'] = get_discord_account()

    res = app.r.set_flair('discordapp', session['reddit']['name'],
                          flair_text='%s#%s' % (session['discord']['username'], session['discord']['discriminator']),
                          flair_css_class=flair_class)

    if len(res['errors']):
        flash('Failed to link accounts!', 'error')
    else:
        flash('Linked Accounts!', 'success')

    return redirect(url_for('.route_index'))


def get_discord_account():
    discord = make_discord_session(token=session.get('discord_token'))
    user = discord.get(app.config['DISCORD_API_BASE_URL'] + '/users/@me').json()
    return user


def get_reddit_account():
    reddit = make_reddit_session(token=session.get('reddit_token'))
    user = reddit.get('https://oauth.reddit.com/api/v1/me', headers={
        'User-Agent': 'Discord Reddit Syncer'
    }).json()
    return user


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 14040)))
