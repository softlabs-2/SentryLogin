<?php namespace Softlabs\SentryLogin;

class SentryLogin
{

    /**
     * Input to be validated
     *
     * @var array
     *
     */
    protected $input;

    /**
     * Validation groups
     *
     * @var array
     *
     */
    public $groups;

    /**
     * Creates a New Validator Instance.
     * @param array $input key value array of fields and there values to be validated.
     *                     uses Input:all() if nothing is passed through
     */
    public function __construct($groups, $input = null)
    {
        $this->groups = $groups ?: [];
        $this->input = $input ?: \Input::all();
    }

    public function authenticate($sessionCallback)
    {
        $rules = array(
            'email' => 'required',
            'password' => 'required',
        );

        $validation = \Validator::make($this->input, $rules);
        if ($validation->fails()) :

            $messages = $validation->messages();

            foreach ($rules as $key => $value) {
                $myArr[$key] = $messages->first($key, ':message');
            }
            $myArr['error'] = 'Email and Password are required.';

            return \Response::json(
                array(
                    'status' => 'ok',
                    'messages' => $myArr
                )
            );

        else:
            try {
                // Set login credentials
                $credentials = array(
                    'email'    => $this->input['email'],
                    'password' => $this->input['password']
                );

                // Try to authenticate the user
                if ($user = \Sentry::authenticate($credentials)):

                    $user = \Sentry::getUserProvider()->findByLogin($user->email);

                    // loop through all groups passed through
                    foreach ($this->groups as $groupName):
                        // get group obj
                        $group = \Sentry::getGroupProvider()->findByName(ucwords($groupName));

                        // check if user belongs to current group
                        if ($user->inGroup($group)) :

                            // logout any previous users
                            \Sentry::logout();

                            $prevUrl = \Session::get('prev_url') ?: '';
                            \Session::forget('prev_url');

                            // Log the user in
                            \Sentry::login($user);

                            // set the session data
                            $sessionCallback($user);

                            return \Response::json(
                                array(
                                    'status' => 'ok',
                                    'url' => $prevUrl,
                                )
                            );

                        else:

                            \Sentry::logout();

                        endif;

                    endforeach;

                    return \Response::json(
                        array(
                            'status' => 'ok',
                            'messages' => array(
                                'error' => 'Error! Email or Password is Invalid.',
                            )
                        )
                    );
                else:
                    // Failed authentication
                endif;

            } catch (\Cartalyst\Sentry\Users\LoginRequiredException $e) {
                return \Response::json(
                    array(
                        'status' => 'ok',
                        'messages' => array(
                            'error' => 'Email is Required',
                            'email' => 'Email is Required'
                        )
                    )
                );
            } catch (\Cartalyst\Sentry\Users\PasswordRequiredException $e) {
                return \Response::json(
                    array(
                        'status' => 'ok',
                        'messages' => array(
                            'error' => 'Password is Required',
                            'password' => 'Password is Required'
                        )
                    )
                );
            } catch (\Cartalyst\Sentry\Users\UserNotActivatedException $e) {
                return \Response::json(
                    array(
                        'status' => 'ok',
                        'messages' => array(
                            'error' => 'Email or Password is Invalid',
                            'email' => 'Email is Invalid',
                            'password' => 'Password is Invalid',
                        )
                    )
                );
            } catch (\Cartalyst\Sentry\Throttling\UserSuspendedException $e) {
                return \Response::json(
                    array(
                        'status' => 'ok',
                        'messages' => array(
                            'error' => 'User has been Suspended. Please wait for 15 minutes before attempting to login again.',
                        )
                    )
                );
            }
            catch (\Cartalyst\Sentry\Throttling\UserBannedException $e) {
                return \Response::json(
                    array(
                        'status' => 'ok',
                        'messages' => array(
                            'error' => 'User is banned. Please contact the System Admin to resolve this.',
                        )
                    )
                );
            } catch (\Cartalyst\Sentry\Users\UserNotFoundException $e)
            {
                return \Response::json(
                    array(
                        'status' => 'ok',
                        'messages' => array(
                            'error' => 'Error! Email or Password is Invalid',
                        )
                    )
                );
            } catch (Exception $e) {
                return \Response::json(
                    array(
                        'status' => 'ok',
                        'messages' => array(
                            'error' => 'Error! Email or Password is Invalid',
                        )
                    )
                );
            }
        endif;
    }

    public function resetPasswordRequest()
    {
        $rules = array(
            'email' => 'required',
        );

        $validation = \Validator::make($this->input, $rules);
        if ($validation->fails()) :

            $messages = $validation->messages();

            foreach ($rules as $key => $value) :
                $myArr[$key] = $messages->first($key, ':message');
            endforeach;

            $myArr['error'] = 'Email is required.';

            return \Response::json(
                array(
                    'status' => 'ok',
                    'messages' => $myArr
                )
            );

        else:
            try
            {
                $user = \Sentry::getUserProvider()->findByLogin($this->input['email']);

                // loop through all groups passed through
                foreach ($this->groups as $groupName):
                    $group = \Sentry::getGroupProvider()->findByName(ucwords($groupName));

                    // check user belongs to current group
                    if ($user->inGroup($group)):

                        $resetCode = $user->getResetPasswordCode();

                        // if groups user type is Admin (1) use admin module
                        if ($group->user_type_id == 1) :

                            $module = 'admin';

                        // else use group name as module
                        else:

                            $module = strtolower($groupName);

                        endif;


                        \Email::sendResetPasswordLink($user, $resetCode, $module);

                        \Session::flash('msg', 'Password Reset Email has been sent.');
                        \Session::flash('tag', 'alert-success');

                        return \Response::json(
                            array(
                                'status' => 'ok',
                                'url' => 'login'
                            )
                        );

                    else:

                        \Sentry::logout();

                    endif;
                endforeach;

                return \Response::json(
                    array(
                        'status' => 'ok',
                        'messages' => array(
                            'error' => 'Error! Email is Invalid',
                        )
                    )
                );

            }
            catch (\Cartalyst\Sentry\Users\UserNotFoundException $e)
            {
                return \Response::json(
                    array(
                        'status' => 'ok',
                        'messages' => array(
                            'error' => 'Error! Email is Invalid',
                        )
                    )
                );
            }
        endif;
    }

    public function resetPassword()
    {
        try
        {
            // Find the user
            $user = \Sentry::getUserProvider()->findByLogin($this->input['email']);

            foreach ($this->groups as $groupName):

                $group = \Sentry::getGroupProvider()->findByName(ucwords($groupName));

                // check user belongs to current group
                if ($user->inGroup($group)) {

                    // Check if the provided password reset code is valid
                    if ($user->checkResetPasswordCode($this->input['code'])) {
                        // The provided password reset code is Valid
                        return \View::make(
                            'login.reset-password',
                            array(
                                'code' => $this->input['code'],
                                'email' => $this->input['email']
                            )
                        );
                    } else {
                        // The provided password reset code is Invalid
                        \Session::flash('msg', 'The Password Reset Email Link has Expired or is Invalid. Please Try Again.');
                        \Session::flash('tag', 'alert-error');
                        return \Redirect::to('login');
                    }
                }
            endforeach;

            // The provided password reset code is Invalid
            \Session::flash('msg', 'The Password Reset Email Link has Expired or is Invalid. Please Try Again.');
            \Session::flash('tag', 'alert-error');
            return \Redirect::to('login');
        }
        catch (\Cartalyst\Sentry\Users\UserNotFoundException $e)
        {
            \Session::flash('msg', 'Error! User does not exist.');
            \Session::flash('tag', 'alert-error');
            return \Redirect::to('login');
        }
    }

    public function saveNewPassword()
    {

         $rules = array(
            'password'      => 'required|same:confirm_password',
            'confirm_password'      => 'required|same:password',
        );

        $validation = \Validator::make($this->input, $rules);

        if ($validation->fails()) :

            $messages = $validation->messages();

            foreach ($rules as $key => $value):
                $myArr[$key] = $messages->first($key, ':message');
            endforeach;

            $myArr['error'] = 'The Password Input Fields do not match.';

            return \Response::json(
                array(
                    'status' => 'ok',
                    'messages' => $myArr
                )
            );

        else:
            try
            {
                // Find the user
                $user = \Sentry::getUserProvider()->findByLogin($this->input['email']);

                foreach ($this->groups as $groupName):
                    $group = \Sentry::getGroupProvider()->findByName(ucwords($groupName));

                    // check user belongs to current group
                    if ($user->inGroup($group)):

                        // Check if the provided password reset code is valid
                        if ($user->attemptResetPassword($this->input['code'], $this->input['password'])):
                            // The provided password reset code is Valid
                            \Session::flash('msg', 'Password Reset. Please login with Your Email Address and New Password');
                            \Session::flash('tag', 'alert-success');
                            return \Response::json(
                                array(
                                    'status' => 'ok',
                                    'url' => '/login'
                                )
                            );
                        else:
                            // The provided password reset code is Invalid
                            \Session::flash('msg', 'The Password Reset Email Link has Expired or is Invalid. Please Try Again.');
                            \Session::flash('tag', 'alert-error');
                            return \Response::json(
                                array(
                                    'status' => 'ok',
                                    'url' => '/login'
                                )
                            );
                        endif;
                    endif;
                endforeach;

                // The provided password reset code is Invalid
                \Session::flash('msg', 'The Password Reset Email Link has Expired or is Invalid. Please Try Again.');
                \Session::flash('tag', 'alert-error');
                return \Response::json(
                    array(
                        'status' => 'ok',
                        'url' => '/login'
                    )
                );
            }
            catch (\Cartalyst\Sentry\Users\UserNotFoundException $e)
            {
                return \Response::json(
                    array(
                        'status' => 'ok',
                        'messages' => array(
                            'error' => 'Error! User does not exist.',
                        )
                    )
                );
            }

        endif;
    }


}