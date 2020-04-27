require "rails/generators/base"

module Rodauth
  module Rails
    module Generators
      class ViewsGenerator < ::Rails::Generators::Base
        source_root "#{__dir__}/templates"
        namespace "rodauth:views"

        VIEWS = {
          login: %w[
            _field _field_error _login_field _login_display _password_field
            _submit _login_form _login_form_footer _login_form_header login
            multi_phase_login
          ],
          create_account: %w[
            _field _field_error _login_field _login_confirm_field
            _password_field _password_confirm_field _submit create_account
          ],
          logout: %w[
            _submit logout
          ],
          reset_password: %w[
            _field _field_error _login_field _login_hidden_field
            _password_field _password_confirm_field _submit
            reset_password_request reset_password
          ],
          remember: %w[
            _submit remember
          ],
          change_login: %w[
            _field _field_error _login_field _login_confirm_field
            _password_field _submit change_login
          ],
          change_password: %w[
            _field _field_error _password_field _new_password_field
            _password_confirm_field _submit change_password
          ],
          close_account: %w[
            _field _field_error _password_field _submit close_account
          ],
          email_auth: %w[
            _login_hidden_field _submit _email_auth_request_form email_auth
          ],
          verify_account: %w[
            _field _field_error _login_hidden_field _login_field _submit
            verify_account_resend verify_account
          ],
          lockout: %w[
            _login_hidden_field _submit unlock_account_request unlock_account
          ],
          active_sessions: %w[
            _global_logout_field
          ],
          two_factor_base: %w[
            _field _field_error password_field _submit
            two_factor_manage two_factor_auth two_factor_disable
          ],
          otp: %w[
            _field _field_error _otp_auth_code_field _password_field _submit
            otp_setup otp_auth otp_disable
          ],
          sms_codes: %w[
            _field _field_error _sms_code_field _sms_phone_field
            _password_field _submit
            sms_setup sms_confirm sms_auth sms_request sms_disable
          ],
          recovery_codes: %w[
            _field _field_error _recovery_code_field _recovery_codes_form
            recovery_codes add_recovery_codes recovery_auth
          ],
          webauthn: %w[
            _field _field_error _login_hidden_field _password_field _submit
            webauthn_setup webauthn_auth_webauthn_remove
          ]
        }

        DEPENDENCIES = {
          active_sessions: :logout,
          otp:             :two_factor_base,
          sms_codes:       :two_factor_base,
          recovery_codes:  :two_factor_base,
          webauthn:        :two_factor_base,
        }

        class_option :features, aliases: "-f", type: :array,
          desc: "Rodauth features to generate views for (login, create_account, reset_password, verify_account etc.)",
          default: %w[login create_account verify_account reset_password change_password change_login verify_login_change close_account]

        def copy_controller
          template "app/controllers/rodauth_controller.rb"
        end

        def copy_helper
          template "app/helpers/rodauth_helper.rb"
        end

        def copy_views
          views = options[:features].inject([]) do |list, feature|
            list |= VIEWS[feature.to_sym] || []
            list |= VIEWS[DEPENDENCIES[feature.to_sym]] || []
          end

          views.each do |view|
            create_file "app/views/rodauth/#{view}.html.erb",
              File.read("#{__dir__}/templates/app/views/rodauth/#{view}.html.erb")
          end
        end
      end
    end
  end
end
