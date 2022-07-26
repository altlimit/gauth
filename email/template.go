package email

var Template = `<!DOCTYPE html>
<html>

<head>
  <meta name="viewport" content="width=device-width" />
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
  <title>{{.Subject}}</title>
  <style>
    @media only screen and (max-width: 620px) {
      table[class="body"] h1 {
        font-size: 28px !important;
        margin-bottom: 10px !important;
      }

      table[class="body"] p,
      table[class="body"] ul,
      table[class="body"] ol,
      table[class="body"] td,
      table[class="body"] span,
      table[class="body"] a {
        font-size: 16px !important;
      }

      table[class="body"] .wrapper,
      table[class="body"] .article {
        padding: 10px !important;
      }

      table[class="body"] .content {
        padding: 0 !important;
      }

      table[class="body"] .container {
        padding: 0 !important;
        width: 100% !important;
      }

      table[class="body"] .main {
        border-left-width: 0 !important;
        border-radius: 0 !important;
        border-right-width: 0 !important;
      }

      table[class="body"] .btn table {
        width: 100% !important;
      }

      table[class="body"] .btn a {
        width: 100% !important;
      }

      table[class="body"] .img-responsive {
        height: auto !important;
        max-width: 100% !important;
        width: auto !important;
      }
    }

    /* -------------------------------------
        PRESERVE THESE STYLES IN THE HEAD
    ------------------------------------- */
    @media all {
      .ExternalClass {
        width: 100%;
      }

      .ExternalClass,
      .ExternalClass p,
      .ExternalClass span,
      .ExternalClass font,
      .ExternalClass td,
      .ExternalClass div {
        line-height: 100%;
      }

      .apple-link a {
        color: inherit !important;
        font-family: inherit !important;
        font-size: inherit !important;
        font-weight: inherit !important;
        line-height: inherit !important;
        text-decoration: none !important;
      }

      #MessageViewBody a {
        color: inherit;
        text-decoration: none;
        font-size: inherit;
        font-family: inherit;
        font-weight: inherit;
        line-height: inherit;
      }

      .btn-primary table td:hover {
        background-color: {{.Primary}} !important;
      }

      .btn-primary a:hover {
        background-color: {{.Primary}} !important;
        border-color: {{.Primary}} !important;
      }
    }
  </style>
</head>

<body class="" style="
      background-color: {{.Neutral}};
      font-family: sans-serif;
      -webkit-font-smoothing: antialiased;
      font-size: 14px;
      line-height: 1.4;
      margin: 0;
      padding: 0;
      -ms-text-size-adjust: 100%;
      -webkit-text-size-adjust: 100%;
    ">
  <table border="0" cellpadding="0" cellspacing="0" class="body" style="
        border-collapse: separate;
        mso-table-lspace: 0pt;
        mso-table-rspace: 0pt;
        width: 100%;
        background-color: {{.Neutral}};
      ">
    <tr>
      <td style="font-family: sans-serif; font-size: 14px; vertical-align: top;">
        &nbsp;
      </td>
      <td class="container" style="
            font-family: sans-serif;
            font-size: 14px;
            vertical-align: top;
            display: block;
            margin: 0 auto;
            max-width: 580px;
            padding: 10px;
            width: 580px;
          ">
        <div class="content" style="
              box-sizing: border-box;
              display: block;
              margin: 0 auto;
              max-width: 580px;
              padding: 10px;
            ">
          <!-- START CENTERED WHITE CONTAINER -->
          <span class="preheader" style="
                color: transparent;
                display: none;
                height: 0;
                max-height: 0;
                max-width: 0;
                opacity: 0;
                overflow: hidden;
                mso-hide: all;
                visibility: hidden;
                width: 0;
              ">
            {{.Subject}}
          </span>
          <table class="main" style="
                border-collapse: separate;
                mso-table-lspace: 0pt;
                mso-table-rspace: 0pt;
                width: 100%;
                background: {{.PrimaryInverse}};
                border-radius: 3px;
              ">
            <!-- START MAIN CONTENT AREA -->
            <tr>
              <td class="wrapper" style="
                    font-family: sans-serif;
                    font-size: 14px;
                    vertical-align: top;
                    box-sizing: border-box;
                    padding: 20px;
                  ">
				{{if .HeaderLabel}}
                <a href="{{.HeaderURL}}" style="text-decoration: none; color:{{.Primary}}; display:flex;align-items: center;justify-content:flex-start;margin-bottom:2rem;padding-bottom:10px;border-bottom:solid 1px {{.Accent}};">
					{{if .LogoURL}}
                 	<img src="{{.LogoURL}}" width="50" height="50"  style="display:block" alt="Logo" title="Logo"/>
				 	{{end}}
                 	<span style="text-decoration: none; font-weight: 300;padding-left: 1rem;font-family:ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, 'Noto Sans', sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Noto Color Emoji';font-size:2rem !important;">{{.HeaderLabel}}</span>
                </a>
				{{end}}
                <table border="0" cellpadding="0" cellspacing="0" style="
                      border-collapse: separate;
                      mso-table-lspace: 0pt;
                      mso-table-rspace: 0pt;
                      width: 100%;
                    ">
                  <tr>
                    <td style="
                          font-family: sans-serif;
                          font-size: 14px;
                          vertical-align: top;
                        ">
                      {{range .Data}}
                      {{if .P}}
                      <p style="
                                font-family: sans-serif;
                                font-size: 14px;
                                font-weight: normal;
                                letter-spacing: 1px;
                                margin: 0;
                                margin-bottom: 15px;
                              ">
                        {{.P}}
                      </p>
                      {{end}}
                      {{if .URL}}
                      <table border="0" cellpadding="0" cellspacing="0" class="btn btn-primary" style="
                              border-collapse: separate;
                              mso-table-lspace: 0pt;
                              mso-table-rspace: 0pt;
                              width: 100%;
                              box-sizing: border-box;
                            ">
                        <tbody>
                          <tr>
                            <td align="left" style="
                                      font-family: sans-serif;
                                      font-size: 14px;
                                      vertical-align: top;
                                      padding-bottom: 15px;
                                    ">
                              <table border="0" cellpadding="0" cellspacing="0" style="
                                        border-collapse: separate;
                                        mso-table-lspace: 0pt;
                                        mso-table-rspace: 0pt;
                                        width: auto;
                                      ">
                                <tbody>
                                  <tr>
                                    <td style="
                                              font-family: sans-serif;
                                              font-size: 14px;
                                              vertical-align: top;
                                              background-color: {{$.Accent}};
                                              border-radius: 5px;
                                              text-align: center;
                                            ">
                                      <a href="{{.URL}}" target="_blank" style="
                                                display: inline-flex;
                                                color: {{$.PrimaryInverse}};
                                                background-color: {{$.Primary}};
                                                border: solid 1px {{$.Primary}};
                                                border-radius: 5px;
                                                box-sizing: border-box;
                                                cursor: pointer;
                                                text-decoration: none;
                                                font-size: 1rem;
                                                font-weight: bold;
                                                margin: 0;
                                                padding: 12px 25px;
                                                text-transform: capitalize;
                                                border-color: {{$.Primary}};
                                                gap:1rem;
                                                align-items: center;
                                              ">
                                              {{.Label}}</a>
                                    </td>
                                  </tr>
                                </tbody>
                              </table>
                            </td>
                          </tr>
                        </tbody>
                      </table>
                      {{end}}
                      {{end}}
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <!-- END MAIN CONTENT AREA -->
          </table>

          {{if .FooterLabel}}
          <div class="footer" style="
                clear: both;
                margin-top: 10px;
                text-align: center;
                width: 100%;
              ">
            <table border="0" cellpadding="0" cellspacing="0" style="
                  border-collapse: separate;
                  mso-table-lspace: 0pt;
                  mso-table-rspace: 0pt;
                  width: 100%;
                ">
              <tr>
                <td class="content-block" style="
                      font-family: sans-serif;
                      vertical-align: top;
                      padding-bottom: 10px;
                      padding-top: 10px;
                      font-size: 12px;
                      color: {{.PrimaryInverse}};
                      text-align: center;
                    ">
                  <a href="{{.FooterURL}}" style="
                        width:100%;
                        text-decoration: underline;
                        color: {{.PrimaryInverse}};
                        font-size: 12px;
                        text-align: center;
                      ">{{.FooterLabel}}</a>
                </td>
              </tr>
            </table>
          </div>
          {{end}}

          <!-- END CENTERED WHITE CONTAINER -->
        </div>
      </td>
      <td style="font-family: sans-serif; font-size: 14px; vertical-align: top;">
        &nbsp;
      </td>
    </tr>
  </table>
</body>

</html>`
