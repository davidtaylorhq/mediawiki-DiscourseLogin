<?php

/**
 * Hooks for DiscourseLogin extension
 *
 */
class DiscourseLoginHooks
{

    static function onUserLoginForm(&$tpl)
    {
        global $wgDiscourseSSOSecret;
        global $wgDiscourseURL;

        $sso_secret = $wgDiscourseSSOSecret;
        $discourse_url = $wgDiscourseURL;
        
        $header = $tpl->get('header');

        $redirectUrl = SpecialPage::getTitleFor('Userlogin')->getFullURL();

        $nonce = hash('sha512', mt_rand());

        // set_key('nonce', $nonce); // pretend that set_key is a function that saves key value data in a database
        $_SESSION["nonce"] = $nonce;

        $payload =  base64_encode( http_build_query( array (
            'nonce' => $nonce,
            'return_sso_url' => $redirectUrl
            )
        ) );
        $request = array(
            'sso' => $payload,
            'sig' => hash_hmac('sha256', $payload, $sso_secret )
            );
        $query = http_build_query($request);
        
        $header .= "<a href='{$discourse_url}/session/sso_provider?{$query}'>Sign in with discourse</a>";


        $tpl->set('header', $header);
    }

    static function onUserLoadFromSession($user)
    {
        global $wgDiscourseSSOSecret;
        global $wgDiscourseURL;

        $sso_secret = $wgDiscourseSSOSecret;
        $discourse_url = $wgDiscourseURL;
        
        global $wgOut;

        if (isset($_GET['sso']) and isset($_GET['sig'])){
            $sso = $_GET['sso'];
            $sig = $_GET['sig'];

            if(hash_hmac('sha256', urldecode($sso), $sso_secret) !== $sig){
                print('SSO Failed');
                return true;
            }
            $sso = urldecode($sso);

            $query = array();
            parse_str(base64_decode($sso), $query);
            
            // verify nonce with generated nonce
            $nonce = $_SESSION["nonce"]; // pretend that get_key is a function that get a value from a database by key
            if($query['nonce'] !== $nonce){
                print('Verification Failed');
                return true;
            }

            // login user
            print_r("This request is valid");
            print_r($query);
            
            $target = $query['email'];

            $dbr = wfGetDB( DB_SLAVE );
            $res = $dbr->select(
                'user',
                array( 'user_name' ),
                array( 'user_email' => $target ),
                __METHOD__
            );
            $loop = 0;
            foreach ( $res as $row ) {
                if ( $loop === 0 ) {
                    $userTarget = $row->user_name;
                }
                if ( !empty( $emailUser ) && ( $emailUser == $row->user_name ) ) {
                    $userTarget = $emailUser;
                }
                $users[] = $row->user_name;
                $loop++;
            }
            $count = $loop;

            if($count > 1){
                print("Multiple users with this email");
                return true;
            }

            if($count == 0){
                $u = User::newFromName($query['username']);
                if ($u->getId() !== 0) { // If user is new
                    print('Username already in use');
                    return true;
                }
                $u->addToDatabase();
                $u->setRealName($query['name']);
                $u->setEmail($query['email']);
                $u->setPassword(PasswordFactory::generateRandomPasswordString());
                $u->setToken();
                $u->confirmEmail();
                $u->saveSettings();

                $ssUpdate = new SiteStatsUpdate(0, 0, 0, 0, 1);
                $ssUpdate->doUpdate(); 

            }else if($count == 1){
                $u = User::newFromName($users[0]);
            }

            $u->setOption("rememberpassword", 1);
            $u->setCookies();

            $wgOut->redirect(Title::newMainPage()->getFullUrl());
        }
        
        return true;

    }
}