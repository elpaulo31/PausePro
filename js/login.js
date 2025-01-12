//LOGIN
const botaoLogin = document.querySelector("#botaoLogar");
const loginForm = document.querySelector("#loginForm");
const errorMessage = document.querySelector("#error-message");


function logar(validando) {
    validando.preventDefault();

    const employeeId = document.querySelector("#employeeId");
    const password = document.querySelector("#password");

    if (employeeId.checkValidity() && password.checkValidity()) {
        errorMessage.style.display = 'none';
        window.location.href = "./pags/logado.html";
    } else {
        errorMessage.style.display = 'block';
    }
}

if (botaoLogin) {
    botaoLogin.addEventListener("click", logar);
}

//CARROSSEL LOGIN
const carrosselLogin = document.querySelector(".carrossel-interno-login");
const itensLogin = document.querySelectorAll(".item-carrossel-login");
let indiceAtualCarrosselLogin = 0;

function moverCarrosselLogin() {
    itensLogin.forEach(item => item.style.display = 'none');

    itensLogin[indiceAtualCarrosselLogin].style.display = 'block';
}

const botaoAnteriorLogin = document.querySelector(".carrossel-login-anterior");
const botaoProximoLogin = document.querySelector(".carrossel-login-proximo");

if (botaoAnteriorLogin && botaoProximoLogin) {
    botaoAnteriorLogin.addEventListener("click", () => {

        indiceAtualCarrosselLogin--;
        if (indiceAtualCarrosselLogin < 0) {
            indiceAtualCarrosselLogin = itensLogin.length - 1;
        }
        moverCarrosselLogin();
    });

    botaoProximoLogin.addEventListener("click", () => {

        indiceAtualCarrosselLogin++;
        if (indiceAtualCarrosselLogin >= itensLogin.length) {
            indiceAtualCarrosselLogin = 0; 
        }
        moverCarrosselLogin();
    });
}

document.addEventListener("DOMContentLoaded", function () {
    moverCarrosselLogin(); 
});

//TRADUCAO LOGIN
function translateToPortugueseLogin() {

    document.querySelector('h1').textContent = 'Login do Funcionário';
    document.querySelector('label[for="employeeId"]').textContent = 'ID do Funcionário:';
    document.querySelector('input#employeeId').placeholder = 'Entre com seu ID do Funcionário';
    document.querySelector('label[for="password"]').textContent = 'Senha:';
    document.querySelector('input#password').placeholder = 'Entre com sua senha'; 
    document.querySelector('button#botaoLogar').textContent = 'Entrar';
    document.querySelector('div[id="error-message"]').textContent = 'Por favor, preencha todos os campos.';

    const carrosselTexts = document.querySelectorAll('.item-carrossel-login p');
    carrosselTexts[0].textContent = 'Empoderando seu dia de trabalho, um check-in de cada vez.';
    carrosselTexts[1].textContent = 'Acompanhamento sem interrupções para você ser mais produtivo.';
    carrosselTexts[2].textContent = 'Fique no horário, mantenha o controle.';
    carrosselTexts[3].textContent = 'Transformando o ponto de entrada em eficiência.';
    carrosselTexts[4].textContent = 'Seu tempo importa, faça cada segundo valer.';

}

function translateToEnglishLogin() {

    document.querySelector('h1').textContent = 'Employee Login';
    document.querySelector('label[for="employeeId"]').textContent = 'Employee ID:';
    document.querySelector('input#employeeId').placeholder = 'Enter your employee ID'; 
    document.querySelector('label[for="password"]').textContent = 'Password:';
    document.querySelector('input#password').placeholder = 'Enter your password'; 
    document.querySelector('button#botaoLogar').textContent = 'Login';
    document.querySelector('div[id="error-message"]').textContent = 'Please fill out this field.';

    const carrosselTexts = document.querySelectorAll('.item-carrossel-login p');
    carrosselTexts[0].textContent = 'Empowering your workday, one check-in at a time.';
    carrosselTexts[1].textContent = 'Seamless tracking for a more productive you.';
    carrosselTexts[2].textContent = 'Stay on time, stay in control.';
    carrosselTexts[3].textContent = 'Transforming attendance into efficiency.';
    carrosselTexts[4].textContent = 'Your time matters, make every second count.';
}

//TRADUTOR LOGIN
const botaoTradutorLogin = document.getElementById('tradutorLogin');
let atualLinguagemLogin = 'en';

function traduzirLogin() {
    if (atualLinguagemLogin === 'en') {
        atualLinguagemLogin = 'pt';
        document.documentElement.lang = 'pt';
        translateToPortugueseLogin();
    } else {
        atualLinguagemLogin = 'en';
        document.documentElement.lang = 'en';
        translateToEnglishLogin();
    }
};

botaoTradutorLogin.addEventListener('click', traduzirLogin);