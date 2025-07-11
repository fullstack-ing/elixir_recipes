defmodule Oauth.Github do
  @doc """
  Generates a url for Github's OAuth.
  
  ## Examples
    
      state = randome_string_generator()
      client_id = Application.fetch!(:some_otp_app, :github_client_id)
      
      iex> authorize_url(client_id, state)
  """
  def authorize_url(client_id, state) do
    "https://github.com/login/oauth/authorize?client_id=#{client_id}&state=#{state}&scope=user:email"
  end

  @doc """
  Exchanges the reponse from OAuth to get user's email.
  
  ## Examples
      opts = [
        code: code,           # From the OAuth response
        state: state,         # From the OAuth response
        client_id: client_id, # From the config
        secret: secret        # From the config
      ]
      iex> Oauth.Github.exchange_access_token(opts)
  """
  def exchange_access_token(opts) do
    opts
    |> fetch_exchange_response()
    |> fetch_user_info()
    |> fetch_emails()
  end

  defp fetch_exchange_response(opts) do
    code = Keyword.fetch!(opts, :code)
    state = Keyword.fetch!(opts, :state)
    client_id = Keyword.fetch!(opts, :client_id)
    secret = Keyword.fetch!(opts, :secret)
    url = "https://github.com/login/oauth/access_token"
    
    body = [
      client_id: client_id,
      client_secret: secret,
      code: code,
      state: state
    ]
    
    case Req.post(url, form: body, headers: [{"accept", "application/json"}]) do
      {:ok, %{status: 200, body: body}} when is_map(body) ->
        case body do
          %{"access_token" => token} -> {:ok, token}
          other -> {:error, {:bad_response, other}}
        end

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_user_info({:error, _reason} = error), do: error
  defp fetch_user_info({:ok, token}) do
    url = "https://api.github.com/user"
    headers = [
      {"accept", "application/vnd.github.v3+json"},
      {"Authorization", "token #{token}"}
    ]
    
    case Req.get(url, headers: headers) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, %{info: body, token: token}}
      
      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}
        
      {:error, reason} -> 
        {:error, reason}
    end
  end

  defp fetch_emails({:error, _} = err), do: err
  defp fetch_emails({:ok, user}) do
    url = "https://api.github.com/user/emails"
    headers = [
      {"accept", "application/vnd.github.v3+json"},
      {"Authorization", "token #{user.token}"}
    ]
    
    case Req.get(url, headers: headers) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, Map.merge(user, %{primary_email: primary_email(body), emails: body})}
      
      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}
        
      {:error, reason} -> 
        {:error, reason}
    end
  end

  defp primary_email(emails) do
    Enum.find(emails, fn email -> email["primary"] end)["email"] || Enum.at(emails, 0)
  end
end