import socket
import subprocess
import platform
from datetime import datetime
from zoneinfo import ZoneInfo
from flask import Flask, render_template, request

app = Flask(__name__)

ARQUIVO_RELATORIO = "relatorio_seguranca.txt"
ARQUIVO_RELATORIO_IP = "relatorio_ip_suspeito.txt"

PORTAS_COMUNS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP"
}

def testar_conectividade(host):
    sistema = platform.system().lower()
    comando = ["ping", "-n", "1", host] if sistema == "windows" else ["ping", "-c", "1", host]

    try:
        resultado = subprocess.run(comando, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return resultado.returncode == 0
    except Exception:
        return False

def verificar_porta(host, porta):
    try:
        socket.setdefaulttimeout(1)
        conexao = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        resultado = conexao.connect_ex((host, porta))
        conexao.close()
        return resultado == 0
    except Exception:
        return False

def verificar_portas(host):
    portas_abertas = []
    for porta, servico in PORTAS_COMUNS.items():
        if verificar_porta(host, porta):
            portas_abertas.append({"porta": porta, "servico": servico})
    return portas_abertas

def classificar_exposicao(portas_abertas):
    quantidade = len(portas_abertas)
    if quantidade == 0:
        return "BAIXO INDÍCIO DE EXPOSIÇÃO"
    elif quantidade <= 3:
        return "ATENÇÃO RECOMENDADA"
    else:
        return "POSSÍVEL EXPOSIÇÃO ELEVADA"

def gerar_recomendacao(classificacao):
    if classificacao == "BAIXO INDÍCIO DE EXPOSIÇÃO":
        return "Nenhuma porta comum foi identificada como aberta. Manter monitoramento periódico."
    elif classificacao == "ATENÇÃO RECOMENDADA":
        return "Verificar se os serviços expostos são realmente necessários e se estão atualizados."
    else:
        return "Revisar regras de firewall, desativar serviços desnecessários e aplicar atualizações de segurança."

def gerar_relatorio(host, conectado, portas_abertas, classificacao, recomendacao):
    data_hora = datetime.now(ZoneInfo("America/Manaus")).strftime("%d/%m/%Y %H:%M:%S")
    with open(ARQUIVO_RELATORIO, "a", encoding="utf-8") as arquivo:
        arquivo.write("\n" + "=" * 60 + "\n")
        arquivo.write("RELATÓRIO DE AUTOMAÇÃO DE SEGURANÇA - NET GUARDIAN\n")
        arquivo.write("=" * 60 + "\n")
        arquivo.write(f"Data/Hora: {data_hora}\n")
        arquivo.write(f"Host analisado: {host}\n")
        arquivo.write(f"Conectividade: {'ATIVO' if conectado else 'INATIVO'}\n")
        arquivo.write("\nPortas abertas encontradas:\n")
        if portas_abertas:
            for item in portas_abertas:
                arquivo.write(f"- Porta {item['porta']} ({item['servico']}) aberta\n")
        else:
            arquivo.write("- Nenhuma porta comum aberta encontrada\n")
        arquivo.write(f"\nClassificação: {classificacao}\n")
        arquivo.write(f"Recomendação: {recomendacao}\n")

def analisar_ip_suspeito(ip, tentativas, portas_distintas, falhas_login, periodo_minutos):
    pontuacao = 0
    evidencias = []

    if tentativas >= 100:
        pontuacao += 4
        evidencias.append("Alto volume de tentativas em curto período")
    elif tentativas >= 50:
        pontuacao += 3
        evidencias.append("Volume considerável de tentativas")
    elif tentativas >= 20:
        pontuacao += 2
        evidencias.append("Volume moderado de tentativas")

    if portas_distintas >= 8:
        pontuacao += 4
        evidencias.append("Muitas portas diferentes acessadas, possível port scan")
    elif portas_distintas >= 4:
        pontuacao += 2
        evidencias.append("Diversas portas acessadas")

    if falhas_login >= 20:
        pontuacao += 4
        evidencias.append("Muitas falhas de login, possível brute force")
    elif falhas_login >= 10:
        pontuacao += 3
        evidencias.append("Falhas de login repetidas")
    elif falhas_login >= 5:
        pontuacao += 2
        evidencias.append("Algumas falhas de login identificadas")

    if periodo_minutos <= 5 and tentativas >= 30:
        pontuacao += 2
        evidencias.append("Atividade concentrada em período muito curto")

    if pontuacao <= 2:
        classificacao = "NORMAL"
        nivel = "BAIXO"
        recomendacao = "Manter monitoramento periódico. Nenhum forte indício de comportamento hostil foi identificado."
    elif pontuacao <= 6:
        classificacao = "SUSPEITO"
        nivel = "MÉDIO"
        recomendacao = "Revisar logs, validar origem do IP e acompanhar novas tentativas."
    else:
        classificacao = "POTENCIALMENTE HOSTIL"
        nivel = "ALTO"
        recomendacao = "Avaliar bloqueio temporário no firewall, revisar contas alvo e verificar possíveis tentativas de ataque."

    if not evidencias:
        evidencias.append("Nenhuma evidência crítica informada")

    return {
        "ip": ip,
        "tentativas": tentativas,
        "portas_distintas": portas_distintas,
        "falhas_login": falhas_login,
        "periodo_minutos": periodo_minutos,
        "pontuacao": pontuacao,
        "classificacao": classificacao,
        "nivel": nivel,
        "evidencias": evidencias,
        "recomendacao": recomendacao,
        "data_hora": datetime.now(ZoneInfo("America/Manaus")).strftime("%d/%m/%Y %H:%M:%S")
    }

def gerar_relatorio_ip(resultado):
    with open(ARQUIVO_RELATORIO_IP, "a", encoding="utf-8") as arquivo:
        arquivo.write("\n" + "=" * 60 + "\n")
        arquivo.write("RELATÓRIO DE ANÁLISE DE IP SUSPEITO - NET GUARDIAN\n")
        arquivo.write("=" * 60 + "\n")
        arquivo.write(f"Data/Hora: {resultado['data_hora']}\n")
        arquivo.write(f"IP analisado: {resultado['ip']}\n")
        arquivo.write(f"Tentativas: {resultado['tentativas']}\n")
        arquivo.write(f"Portas distintas: {resultado['portas_distintas']}\n")
        arquivo.write(f"Falhas de login: {resultado['falhas_login']}\n")
        arquivo.write(f"Período analisado: {resultado['periodo_minutos']} minutos\n")
        arquivo.write(f"Pontuação: {resultado['pontuacao']}\n")
        arquivo.write(f"Classificação: {resultado['classificacao']}\n")
        arquivo.write(f"Nível de risco: {resultado['nivel']}\n")
        arquivo.write("\nEvidências:\n")
        for evidencia in resultado["evidencias"]:
            arquivo.write(f"- {evidencia}\n")
        arquivo.write(f"\nRecomendação: {resultado['recomendacao']}\n")

@app.route("/", methods=["GET", "POST"])
def index():
    resultado_host = None
    resultado_ip = None

    if request.method == "POST":
        tipo_analise = request.form.get("tipo_analise")

        if tipo_analise == "host":
            host = request.form.get("host", "").strip()
            if host:
                conectado = testar_conectividade(host)
                portas_abertas = verificar_portas(host)
                classificacao = classificar_exposicao(portas_abertas)
                recomendacao = gerar_recomendacao(classificacao)
                gerar_relatorio(host, conectado, portas_abertas, classificacao, recomendacao)

                total_portas = len(PORTAS_COMUNS)
                abertas = len(portas_abertas)
                fechadas = total_portas - abertas

                resultado_host = {
                    "host": host,
                    "conectividade": "ATIVO" if conectado else "INATIVO",
                    "portas_abertas": portas_abertas,
                    "classificacao": classificacao,
                    "recomendacao": recomendacao,
                    "data_hora": datetime.now(ZoneInfo("America/Manaus")).strftime("%d/%m/%Y %H:%M:%S"),
                    "total_portas": total_portas,
                    "abertas": abertas,
                    "fechadas": fechadas
                }

        elif tipo_analise == "ip_suspeito":
            ip = request.form.get("ip_suspeito", "").strip()
            tentativas = int(request.form.get("tentativas", 0))
            portas_distintas = int(request.form.get("portas_distintas", 0))
            falhas_login = int(request.form.get("falhas_login", 0))
            periodo_minutos = int(request.form.get("periodo_minutos", 1))

            resultado_ip = analisar_ip_suspeito(
                ip,
                tentativas,
                portas_distintas,
                falhas_login,
                periodo_minutos
            )
            gerar_relatorio_ip(resultado_ip)

    return render_template("index.html", resultado_host=resultado_host, resultado_ip=resultado_ip)

if __name__ == "__main__":
    app.run(debug=True)
