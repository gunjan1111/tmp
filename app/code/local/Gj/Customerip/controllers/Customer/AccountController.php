<?php require_once "Mage/Customer/controllers/AccountController.php";  
class Gj_Customerip_Customer_AccountController extends Mage_Customer_AccountController
{
    public function postDispatch()
    {
        parent::postDispatch();
        Mage::dispatchEvent('controller_action_postdispatch_adminhtml', array('controller_action' => $this));
    }

    public function createPostAction()
    {
        $errUrl = $this->_getUrl('*/*/create', array('_secure' => true));

        if (!$this->_validateFormKey()) {
            $this->_redirectError($errUrl);
            return;
        }

        $post = $this->getRequest()->getPost();

        if((filter_var($post['email'], FILTER_VALIDATE_EMAIL)) && (strpos($post['email'],'qq.com') !== false || strpos($post['email'],'yijia.com') !== false))
        //if((filter_var($post['email'], FILTER_VALIDATE_EMAIL)) && (strpos($post['email'],'qq.com') !== false || strpos($post['email'],'.cn') !== false || strpos($post['email'],'.ru') !== false))
        {
            Mage::getSingleton('core/session')->addError("We take website security seriously. We're sorry, but ".$post['email']." is not consider a safe email address. Please use an email with a different domain name host.");
            $this->_redirectReferer();
            return;
        }

        // Check the existance of reCaptcha in request
        if (!isset($post['g-recaptcha-response'])) {
            $this->_redirect('*/');
            return;
        }
        require_once(Mage::getBaseDir('lib') . DS . 'reCaptcha' . DS . 'recaptchalib.php');
        $privatekey = '6LcrwSkUAAAAAJmqQ_e22-tgojEvUkVKGExSV-S7';
        $resp = null;
        $reCaptcha = new ReCaptcha($privatekey);
        $remote_addr = $this->getRequest()->getServer('REMOTE_ADDR');
        $resp = $reCaptcha->verifyResponse(
            $remote_addr,
            $post['g-recaptcha-response']
        );

        // If customer did not check reCaptcha
        if ($resp->errorCodes == "missing-input") {
            Mage::getSingleton('core/session')->addError('Please check the reCaptcha');
            $this->_redirectReferer();
            return;
        }

        // If reCaptcha verified successfully
        if ($resp != null && $resp->success) {
            /*$this->_save();
            $this->_redirectReferer();
            return;*/

            /** @var $session Mage_Customer_Model_Session */
            $session = $this->_getSession();
            if ($session->isLoggedIn()) {
                $this->_redirect('*/*/');
                return;
            }

            if (!$this->getRequest()->isPost()) {
                $this->_redirectError($errUrl);
                return;
            }

            $customer = $this->_getCustomer();

            try {
                $errors = $this->_getCustomerErrors($customer);

                if (empty($errors)) {
                    $customer->cleanPasswordsValidationData();
                    //$customer->setPasswordCreatedAt(time());
                    $customer->save();
                    $this->_dispatchRegisterSuccess($customer);
                    $this->_successProcessRegistration($customer);
                    return;
                } else {
                    $this->_addSessionError($errors);
                }
            } catch (Mage_Core_Exception $e) {
                $session->setCustomerFormData($this->getRequest()->getPost());
                if ($e->getCode() === Mage_Customer_Model_Customer::EXCEPTION_EMAIL_EXISTS) {
                    $url = $this->_getUrl('customer/account/forgotpassword');
                    $message = $this->__('There is already an account with this email address. If you are sure that it is your email address, <a href="%s">click here</a> to get your password and access your account.', $url);
                } else {
                    $message = $this->_escapeHtml($e->getMessage());
                }
                $session->addError($message);
            } catch (Exception $e) {
                $session->setCustomerFormData($this->getRequest()->getPost());
                $session->addException($e, $this->__('Cannot save the customer.'));
            }

        } else {
        Mage::getSingleton('core/session')->addError('An error has occured because of reCaptcha. Please try again!');
        $this->_redirectReferer();
        return;
        }

        $this->_redirectError($errUrl);
    }

    public function loginPostAction()
    {
        if (!$this->_validateFormKey()) {
            $this->_redirect('*/*/');
            return;
        }

        if ($this->_getSession()->isLoggedIn()) {
            $this->_redirect('*/*/');
            return;
        }
        $session = $this->_getSession();

        if ($this->getRequest()->isPost()) {
            $login = $this->getRequest()->getPost('login');

            if(!empty($login['username']) && (strpos($login['username'],'qq.com') !== false || strpos($login['username'],'yijia.com') !== false))
            {
                $session->addError($this->__("We take website security seriously. We're sorry, but ".$login['username']." is not consider a safe email address. Please use an email with a different domain name host."));
                $this->_redirect('*/*/');
                return;
            }

            if (!empty($login['username']) && !empty($login['password'])) {
                try {
                    $session->login($login['username'], $login['password']);
                    if ($session->getCustomer()->getIsJustConfirmed()) {
                        $this->_welcomeCustomer($session->getCustomer(), true);
                    }
                } catch (Mage_Core_Exception $e) {
                    switch ($e->getCode()) {
                        case Mage_Customer_Model_Customer::EXCEPTION_EMAIL_NOT_CONFIRMED:
                            $value = $this->_getHelper('customer')->getEmailConfirmationUrl($login['username']);
                            $message = $this->_getHelper('customer')->__('This account is not confirmed. <a href="%s">Click here</a> to resend confirmation email.', $value);
                            break;
                        case Mage_Customer_Model_Customer::EXCEPTION_INVALID_EMAIL_OR_PASSWORD:
                            $message = $e->getMessage();
                            break;
                        default:
                            $message = $e->getMessage();
                    }
                    $session->addError($message);
                    $session->setUsername($login['username']);
                } catch (Exception $e) {
                    // Mage::logException($e); // PA DSS violation: this exception log can disclose customer password
                }
            } else {
                $session->addError($this->__('Login and password are required.'));
            }
        }

        $this->_loginPostRedirect();
    }
}
