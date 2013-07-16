<?php namespace Softlabs\SentryLogin;

use Illuminate\Support\ServiceProvider;

class SentryLoginServiceProvider extends ServiceProvider {

	/**
	 * Indicates if loading of the provider is deferred.
	 *
	 * @var bool
	 */
	protected $defer = false;

    /**
     * Bootstrap the application events.
     *
     * @return void
     */
    public function boot()
    {
        $this->package('softlabs/sentrylogin');
    }

	/**
	 * Register the service provider.
	 *
	 * @return void
	 */
	public function register()
	{
		$this->app['sentrylogin'] = $this->app->share(function($app)
        {
            return new SentryLogin;
        });
	}

	/**
	 * Get the services provided by the provider.
	 *
	 * @return array
	 */
	public function provides()
	{
		return array('sentrylogin');
	}

}